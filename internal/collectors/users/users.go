package users

import (
	"context"
	"strconv"
	"strings"

	"linux-dfir/internal/collectors/common"
	"linux-dfir/internal/evidence"
	"linux-dfir/internal/output"
)

type User struct {
	evidence.RecordMeta
	Name  string `json:"name"`
	UID   int    `json:"uid"`
	GID   int    `json:"gid"`
	Gecos string `json:"gecos,omitempty"`
	Home  string `json:"home"`
	Shell string `json:"shell"`
}

type Group struct {
	evidence.RecordMeta
	Name    string   `json:"name"`
	GID     int      `json:"gid"`
	Members []string `json:"members"`
}

type UserEntity struct {
	evidence.RecordMeta
	EntityType          string               `json:"entity_type"`
	EntityID            string               `json:"entity_id"`
	Name                string               `json:"name"`
	UID                 int                  `json:"uid"`
	GID                 int                  `json:"gid"`
	PrimaryGroup        string               `json:"primary_group,omitempty"`
	Gecos               string               `json:"gecos,omitempty"`
	Home                string               `json:"home"`
	Shell               string               `json:"shell"`
	SupplementaryGroups []string             `json:"supplementary_groups,omitempty"`
	Sources             []evidence.SourceRef `json:"sources,omitempty"`
}

type GroupEntity struct {
	evidence.RecordMeta
	EntityType string               `json:"entity_type"`
	EntityID   string               `json:"entity_id"`
	Name       string               `json:"name"`
	GID        int                  `json:"gid"`
	Members    []string             `json:"members"`
	Sources    []evidence.SourceRef `json:"sources,omitempty"`
}

func Collect(ctx context.Context, out *output.Manager) error {
	_ = ctx
	var passwdPath string
	var groupPath string
	var parsedUsers []User
	var parsedGroups []Group
	if path, text, err := common.ReadFirstExisting("/etc/passwd"); err == nil {
		passwdPath = path
		if err := out.WriteLegacyFromSource("system/user/passwd", []byte(text), "users", path, "file", "high"); err != nil {
			return err
		}
		common.TimelineFileStat(out, "users", path, "legacy/system/user/passwd")
		parsedUsers = ParsePasswd(text)
	} else {
		_ = out.Error(evidence.ErrorEvent{Collector: "users", Error: err.Error(), SourcePath: "/etc/passwd", SourceType: "file", SourceTrust: "high"})
	}

	if path, text, err := common.ReadFirstExisting("/etc/group"); err == nil {
		groupPath = path
		if err := out.WriteLegacyFromSource("system/user/group", []byte(text), "users", path, "file", "high"); err != nil {
			return err
		}
		common.TimelineFileStat(out, "users", path, "legacy/system/user/group")
		parsedGroups = ParseGroup(text)
	} else {
		_ = out.Error(evidence.ErrorEvent{Collector: "users", Error: err.Error(), SourcePath: "/etc/group", SourceType: "file", SourceTrust: "high"})
	}

	if path, text, err := common.ReadFirstExisting("/etc/sudoers"); err == nil {
		if err := out.WriteLegacyFromSource("system/user/sudoers", []byte(text), "users", path, "file", "high"); err != nil {
			return err
		}
		common.TimelineFileStat(out, "users", path, "legacy/system/user/sudoers")
	}
	if err := writeUserEntities(out, passwdPath, parsedUsers, groupPath, parsedGroups); err != nil {
		return err
	}
	return writeGroupEntities(out, groupPath, parsedGroups)
}

func ParsePasswd(text string) []User {
	var result []User
	for _, line := range common.Lines(text) {
		if strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 7 {
			continue
		}
		uid, errUID := strconv.Atoi(parts[2])
		gid, errGID := strconv.Atoi(parts[3])
		if errUID != nil || errGID != nil {
			continue
		}
		result = append(result, User{Name: parts[0], UID: uid, GID: gid, Gecos: parts[4], Home: parts[5], Shell: parts[6]})
	}
	return result
}

func ParseGroup(text string) []Group {
	var result []Group
	for _, line := range common.Lines(text) {
		if strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 4 {
			continue
		}
		gid, err := strconv.Atoi(parts[2])
		if err != nil {
			continue
		}
		members := []string{}
		if parts[3] != "" {
			members = strings.Split(parts[3], ",")
		}
		result = append(result, Group{Name: parts[0], GID: gid, Members: members})
	}
	return result
}

func writeUserEntities(out *output.Manager, passwdPath string, users []User, groupPath string, groups []Group) error {
	primaryGroups := map[int]string{}
	supplementaryByUser := map[string][]string{}
	for _, group := range groups {
		if _, ok := primaryGroups[group.GID]; !ok {
			primaryGroups[group.GID] = group.Name
		}
		for _, member := range group.Members {
			supplementaryByUser[member] = append(supplementaryByUser[member], group.Name)
		}
	}
	sourcePath := firstNonEmpty(passwdPath, groupPath, "/etc/passwd,/etc/group")
	for _, user := range users {
		supplementary := uniqueSorted(supplementaryByUser[user.Name])
		record := UserEntity{
			RecordMeta:          out.Meta("users", "entities/user.jsonl", sourcePath, "file", "high"),
			EntityType:          "user",
			EntityID:            "user:" + strconv.Itoa(user.UID),
			Name:                user.Name,
			UID:                 user.UID,
			GID:                 user.GID,
			PrimaryGroup:        primaryGroups[user.GID],
			Gecos:               user.Gecos,
			Home:                user.Home,
			Shell:               user.Shell,
			SupplementaryGroups: supplementary,
			Sources: []evidence.SourceRef{
				{SourcePath: firstNonEmpty(passwdPath, "/etc/passwd"), SourceType: "file", SourceTrust: "high", RawArtifactRef: "legacy/system/user/passwd"},
				{SourcePath: firstNonEmpty(groupPath, "/etc/group"), SourceType: "file", SourceTrust: "high", RawArtifactRef: "legacy/system/user/group"},
			},
		}
		if err := out.AppendAIJSONL("entities/user.jsonl", record, "users", sourcePath, "file", "high"); err != nil {
			return err
		}
	}
	return nil
}

func writeGroupEntities(out *output.Manager, groupPath string, groups []Group) error {
	sourcePath := firstNonEmpty(groupPath, "/etc/group")
	for _, group := range groups {
		record := GroupEntity{
			RecordMeta: out.Meta("users", "entities/group.jsonl", sourcePath, "file", "high"),
			EntityType: "group",
			EntityID:   "group:" + strconv.Itoa(group.GID),
			Name:       group.Name,
			GID:        group.GID,
			Members:    uniqueSorted(group.Members),
			Sources: []evidence.SourceRef{
				{SourcePath: firstNonEmpty(groupPath, "/etc/group"), SourceType: "file", SourceTrust: "high", RawArtifactRef: "legacy/system/user/group"},
			},
		}
		if err := out.AppendAIJSONL("entities/group.jsonl", record, "users", sourcePath, "file", "high"); err != nil {
			return err
		}
	}
	return nil
}

func uniqueSorted(values []string) []string {
	seen := map[string]bool{}
	result := []string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	for i := 0; i < len(result); i++ {
		for j := i + 1; j < len(result); j++ {
			if result[j] < result[i] {
				result[i], result[j] = result[j], result[i]
			}
		}
	}
	return result
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
