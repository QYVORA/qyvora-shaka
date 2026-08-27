package cli

import (
	"strconv"

	"github.com/QYVORA/qyvora-shaka/pkg/models"
)

func userRows(users []*models.User) [][]string {
	rows := make([][]string, 0, len(users))
	for _, u := range users {
		rows = append(rows, []string{
			u.SAMAccount, u.Name, u.UPN, enabledStr(u.Enabled), yes(u.AdminCount),
		})
	}
	return rows
}

func groupRows(groups []*models.Group) [][]string {
	rows := make([][]string, 0, len(groups))
	for _, g := range groups {
		rows = append(rows, []string{
			g.SAMAccount, g.Name, yes(g.IsSecurity), yes(g.AdminCount),
			strconv.Itoa(len(g.Members)),
		})
	}
	return rows
}

func computerRows(comps []*models.Computer) [][]string {
	rows := make([][]string, 0, len(comps))
	for _, c := range comps {
		rows = append(rows, []string{c.Name, c.OperatingSystem, c.DNSName, enabledStr(c.Enabled)})
	}
	return rows
}

func ouRows(ous []*models.OrganizationalUnit) [][]string {
	rows := make([][]string, 0, len(ous))
	for _, o := range ous {
		rows = append(rows, []string{o.Name, o.DistName})
	}
	return rows
}

func trustRows(trusts []*models.Trust) [][]string {
	rows := make([][]string, 0, len(trusts))
	for _, t := range trusts {
		rows = append(rows, []string{t.SourceDomain, t.TargetDomain, t.Direction, t.Type})
	}
	return rows
}

func findingRows(fs []*models.Finding) [][]string {
	rows := make([][]string, 0, len(fs))
	for _, f := range fs {
		rows = append(rows, []string{
			string(f.Severity), f.RuleID, f.Title, string(f.Confidence), f.TargetID,
		})
	}
	return rows
}

func evidenceRows(es []*models.Evidence) [][]string {
	rows := make([][]string, 0, len(es))
	for _, ev := range es {
		rows = append(rows, []string{ev.ID, ev.Kind, ev.Hash, ev.Source})
	}
	return rows
}

func edgeRows(edges []*models.Edge) [][]string {
	rows := make([][]string, 0, len(edges))
	for _, e := range edges {
		rows = append(rows, []string{e.From, string(e.Type), e.To, string(e.Confidence)})
	}
	return rows
}

func enabledStr(b *bool) string {
	if b == nil {
		return "-"
	}
	if *b {
		return "yes"
	}
	return "no"
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
