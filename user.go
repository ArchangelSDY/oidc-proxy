package main

import (
	"encoding/json"

	"github.com/coreos/go-oidc"
)

type UserContext struct {
	UserName string
	Groups   []string
}

func ParseUserContext(opts *Options, token *oidc.IDToken) (*UserContext, error) {
	var claims map[string]json.RawMessage
	if err := token.Claims(&claims); err != nil {
		return nil, err
	}

	var userContext UserContext

	if val, ok := claims[opts.UserClaim]; ok {
		var userName string
		if err := json.Unmarshal(val, &userName); err == nil {
			userContext.UserName = opts.UserPrefix + userName
		}
	}

	if val, ok := claims[opts.GroupsClaim]; ok {
		var group string
		if err := json.Unmarshal(val, &group); err == nil {
			userContext.Groups = []string{opts.GroupsPrefix + group}
		}

		var groups []string
		if err := json.Unmarshal(val, &groups); err == nil {
			userContext.Groups = make([]string, len(groups), len(groups))
			for i, group := range groups {
				userContext.Groups[i] = opts.GroupsPrefix + group
			}
		}
	}

	return &userContext, nil
}
