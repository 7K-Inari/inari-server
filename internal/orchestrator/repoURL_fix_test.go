package orchestrator
import "testing"
func TestRepoURLCasing(t *testing.T) {
	if got := repoURL("7K-Group/7kgroup-inari-state"); got != "https://github.com/7k-group/7kgroup-inari-state" {
		t.Errorf("got %q", got)
	}
	if got := repoURL("https://github.com/7K-Group/Repo"); got != "https://github.com/7k-group/Repo" {
		t.Errorf("got %q", got)
	}
}
