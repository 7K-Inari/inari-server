package scaffold

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/7K-Inari/inari-server/internal/types"
)

func testRun() *types.ScaffoldRun {
	return &types.ScaffoldRun{
		ID: "run:1", OrgID: "org:acme", TemplateItemID: "template:go-service",
		TemplateVersion: "1.0.0", Phase: types.ScaffoldPhasePending,
	}
}

func collectStepUpdates() (OnUpdate, *[]string) {
	var seq []string
	return func(_ context.Context, _ *RunContext, st *types.ScaffoldRunStep) error {
		seq = append(seq, st.Name+":"+st.State)
		return nil
	}, &seq
}

// orderedSteps builds a fake registry of n steps in order a,b,c,....
func orderedSteps(names []string, fns map[string]StepFunc) (map[string]*types.ScaffoldRunStep, map[string]StepFunc) {
	steps := map[string]*types.ScaffoldRunStep{}
	for _, n := range names {
		steps[n] = &types.ScaffoldRunStep{RunID: "run:1", Name: n, State: types.ScaffoldStepPending, MaxAttempts: 3}
	}
	return steps, fns
}

var abc = []string{"a", "b", "c"}

func TestRunStepsHappyPath(t *testing.T) {
	var calls []string
	fn := func(name string) StepFunc {
		return func(context.Context, *ExecEnv, *RunContext, *types.ScaffoldRunStep) (bool, error) {
			calls = append(calls, name)
			return true, nil
		}
	}
	steps, funcs := orderedSteps(abc, map[string]StepFunc{"a": fn("a"), "b": fn("b"), "c": fn("c")})
	rc := &RunContext{Run: testRun(), Steps: steps, Actor: "dev-1"}
	onUpdate, seq := collectStepUpdates()

	complete, err := RunSteps(context.Background(), &ExecEnv{}, rc, abc, funcs, onUpdate, nil)
	if err != nil || !complete {
		t.Fatalf("complete=%v err=%v", complete, err)
	}
	if strings.Join(calls, ",") != "a,b,c" {
		t.Fatalf("steps ran out of order: %v", calls)
	}
	if got := strings.Join(*seq, ","); got != "a:completed,b:completed,c:completed" {
		t.Fatalf("updates = %v", got)
	}
}

func TestRunStepsSkipsCompletedSteps(t *testing.T) {
	ran := 0
	fn := func(context.Context, *ExecEnv, *RunContext, *types.ScaffoldRunStep) (bool, error) {
		ran++
		return true, nil
	}
	steps, funcs := orderedSteps(abc, map[string]StepFunc{"a": fn, "b": fn, "c": fn})
	steps["a"].State = types.ScaffoldStepCompleted // idempotent re-entry
	rc := &RunContext{Run: testRun(), Steps: steps, Actor: "dev-1"}
	onUpdate, _ := collectStepUpdates()

	complete, err := RunSteps(context.Background(), &ExecEnv{}, rc, abc, funcs, onUpdate, nil)
	if err != nil || !complete {
		t.Fatalf("complete=%v err=%v", complete, err)
	}
	if ran != 2 {
		t.Fatalf("completed step re-executed: ran=%d", ran)
	}
}

func TestRunStepsWaitingStopsChainWithoutAttempt(t *testing.T) {
	steps, funcs := orderedSteps(abc, map[string]StepFunc{
		"a": func(context.Context, *ExecEnv, *RunContext, *types.ScaffoldRunStep) (bool, error) { return true, nil },
		"b": func(context.Context, *ExecEnv, *RunContext, *types.ScaffoldRunStep) (bool, error) { return false, nil },
		"c": func(context.Context, *ExecEnv, *RunContext, *types.ScaffoldRunStep) (bool, error) {
			t.Fatal("c must not run while b waits")
			return true, nil
		},
	})
	rc := &RunContext{Run: testRun(), Steps: steps, Actor: "dev-1"}
	onUpdate, _ := collectStepUpdates()

	complete, err := RunSteps(context.Background(), &ExecEnv{}, rc, abc, funcs, onUpdate, nil)
	if err != nil || complete {
		t.Fatalf("complete=%v err=%v, want waiting", complete, err)
	}
	if steps["b"].State != types.ScaffoldStepWaiting || steps["b"].Attempts != 0 {
		t.Fatalf("waiting consumed an attempt: %+v", steps["b"])
	}
}

func TestRunStepsFailureConsumesAttemptAndRetries(t *testing.T) {
	failures := 0
	steps, funcs := orderedSteps(abc, map[string]StepFunc{
		"a": func(context.Context, *ExecEnv, *RunContext, *types.ScaffoldRunStep) (bool, error) {
			if failures < 2 {
				failures++
				return false, errors.New("boom")
			}
			return true, nil
		},
		"b": func(context.Context, *ExecEnv, *RunContext, *types.ScaffoldRunStep) (bool, error) { return true, nil },
		"c": func(context.Context, *ExecEnv, *RunContext, *types.ScaffoldRunStep) (bool, error) { return true, nil },
	})
	rc := &RunContext{Run: testRun(), Steps: steps, Actor: "dev-1"}
	onUpdate, _ := collectStepUpdates()

	// First two drives fail on step a.
	for i := 0; i < 2; i++ {
		if _, err := RunSteps(context.Background(), &ExecEnv{}, rc, abc, funcs, onUpdate, nil); err == nil {
			t.Fatalf("drive %d: want failure", i)
		}
	}
	if steps["a"].Attempts != 2 || steps["a"].Error != "boom" {
		t.Fatalf("attempts not counted: %+v", steps["a"])
	}
	// Third drive succeeds end-to-end.
	complete, err := RunSteps(context.Background(), &ExecEnv{}, rc, abc, funcs, onUpdate, nil)
	if err != nil || !complete {
		t.Fatalf("retry did not complete: complete=%v err=%v", complete, err)
	}
	if steps["a"].Attempts != 2 {
		t.Fatalf("success must not consume an extra attempt: %+v", steps["a"])
	}
}

func TestRunStepsCancelMidRun(t *testing.T) {
	cancelled := false
	steps, funcs := orderedSteps(abc, map[string]StepFunc{
		"a": func(context.Context, *ExecEnv, *RunContext, *types.ScaffoldRunStep) (bool, error) {
			cancelled = true // cancel lands while step a runs
			return true, nil
		},
		"b": func(context.Context, *ExecEnv, *RunContext, *types.ScaffoldRunStep) (bool, error) {
			t.Fatal("b must not run after cancel")
			return true, nil
		},
		"c": func(context.Context, *ExecEnv, *RunContext, *types.ScaffoldRunStep) (bool, error) { return true, nil },
	})
	rc := &RunContext{Run: testRun(), Steps: steps, Actor: "dev-1"}
	onUpdate, seq := collectStepUpdates()

	_, err := RunSteps(context.Background(), &ExecEnv{}, rc, abc, funcs, onUpdate, func() bool { return cancelled })
	if !errors.Is(err, ErrCancelled) {
		t.Fatalf("err = %v, want ErrCancelled", err)
	}
	if steps["b"].State != types.ScaffoldStepFailed || steps["b"].Error != "cancelled" {
		t.Fatalf("cancelled step = %+v", steps["b"])
	}
	if steps["b"].Attempts != 0 {
		t.Fatalf("cancel must not consume the attempt budget: %+v", steps["b"])
	}
	want := "a:completed,b:failed"
	if got := strings.Join(*seq, ","); got != want {
		t.Fatalf("updates = %v, want %v", got, want)
	}
}

func TestRunStepsPlaceholderRegistryParksAtRegisteringCatalog(t *testing.T) {
	// Seed a run whose W3/W4-implemented steps already completed; the real
	// registry must park at the remaining W4 placeholder without consuming
	// attempts.
	run := testRun()
	steps := map[string]*types.ScaffoldRunStep{}
	for _, n := range stepNames {
		steps[n] = &types.ScaffoldRunStep{RunID: run.ID, Name: n, State: types.ScaffoldStepPending, MaxAttempts: 5}
	}
	steps["rendering"].State = types.ScaffoldStepCompleted
	steps["creating-repo"].State = types.ScaffoldStepCompleted
	steps["creating-pipeline"].State = types.ScaffoldStepCompleted
	rc := &RunContext{Run: run, Steps: steps, Actor: "dev-1"}
	onUpdate, _ := collectStepUpdates()

	complete, err := RunSteps(context.Background(), &ExecEnv{}, rc, stepNames, stepFuncs, onUpdate, nil)
	if err != nil || complete {
		t.Fatalf("complete=%v err=%v, want parked", complete, err)
	}
	st := steps["registering-catalog"]
	if st.State != types.ScaffoldStepWaiting || st.Attempts != 0 {
		t.Fatalf("placeholder consumed attempts: %+v", st)
	}
}
