// Copyright (c) 2017-present Mattermost, Inc. All Rights Reserved.
// See License.txt for license information.

package app

import (
	"encoding/json"
	"net/http"
	"strings"

	l4g "github.com/alecthomas/log4go"

	"github.com/gorilla/mux"
	"github.com/mattermost/platform/einterfaces"
	"github.com/mattermost/platform/model"
	"github.com/mattermost/platform/utils"

	"github.com/mattermost/platform/app/plugin"
	"github.com/mattermost/platform/app/plugin/jira"
	"github.com/mattermost/platform/app/plugin/ldapextras"
)

type PluginAPI struct {
	id     string
	router *mux.Router
}

func (api *PluginAPI) LoadPluginConfiguration(dest interface{}) error {
	if b, err := json.Marshal(utils.Cfg.PluginSettings.Plugins[api.id]); err != nil {
		return err
	} else {
		return json.Unmarshal(b, dest)
	}
}

func (api *PluginAPI) PluginRouter() *mux.Router {
	return api.router
}

func (api *PluginAPI) GetTeamByName(name string) (*model.Team, *model.AppError) {
	return GetTeamByName(name)
}

func (api *PluginAPI) GetUserByName(name string) (*model.User, *model.AppError) {
	return GetUserByUsername(name)
}

func (api *PluginAPI) GetChannelByName(teamId, name string) (*model.Channel, *model.AppError) {
	return GetChannelByName(name, teamId)
}

func (api *PluginAPI) GetDirectChannel(userId1, userId2 string) (*model.Channel, *model.AppError) {
	return GetDirectChannel(userId1, userId2)
}

func (api *PluginAPI) CreatePost(post *model.Post) (*model.Post, *model.AppError) {
	return CreatePostMissingChannel(post, true)
}

func (api *PluginAPI) GetLdapUserAttributes(userId string, attributes []string) (map[string]string, *model.AppError) {
	ldapInterface := einterfaces.GetLdapInterface()
	if ldapInterface == nil {
		return nil, model.NewAppError("GetLdapUserAttributes", "ent.ldap.disabled.app_error", nil, "", http.StatusNotImplemented)
	}

	user, err := GetUser(userId)
	if err != nil {
		return nil, err
	}

	return ldapInterface.GetUserAttributes(*user.AuthData, attributes)
}

func (api *PluginAPI) GetSessionFromRequest(r *http.Request) (*model.Session, *model.AppError) {
	token := ""
	isTokenFromQueryString := false

	// Attempt to parse token out of the header
	authHeader := r.Header.Get(model.HEADER_AUTH)
	if len(authHeader) > 6 && strings.ToUpper(authHeader[0:6]) == model.HEADER_BEARER {
		// Default session token
		token = authHeader[7:]

	} else if len(authHeader) > 5 && strings.ToLower(authHeader[0:5]) == model.HEADER_TOKEN {
		// OAuth token
		token = authHeader[6:]
	}

	// Attempt to parse the token from the cookie
	if len(token) == 0 {
		if cookie, err := r.Cookie(model.SESSION_COOKIE_TOKEN); err == nil {
			token = cookie.Value

			if r.Header.Get(model.HEADER_REQUESTED_WITH) != model.HEADER_REQUESTED_WITH_XML {
				return nil, model.NewAppError("ServeHTTP", "api.context.session_expired.app_error", nil, "token="+token+" Appears to be a CSRF attempt", http.StatusUnauthorized)
			}
		}
	}

	// Attempt to parse token out of the query string
	if len(token) == 0 {
		token = r.URL.Query().Get("access_token")
		isTokenFromQueryString = true
	}

	if len(token) == 0 {
		return nil, model.NewAppError("ServeHTTP", "api.context.session_expired.app_error", nil, "token="+token, http.StatusUnauthorized)
	}

	session, err := GetSession(token)

	if err != nil {
		return nil, model.NewAppError("ServeHTTP", "api.context.session_expired.app_error", nil, "token="+token, http.StatusUnauthorized)
	} else if !session.IsOAuth && isTokenFromQueryString {
		return nil, model.NewAppError("ServeHTTP", "api.context.token_provided.app_error", nil, "token="+token, http.StatusUnauthorized)
	}

	return session, nil
}

func (api *PluginAPI) I18n(id string, r *http.Request) string {
	if r != nil {
		f, _ := utils.GetTranslationsAndLocale(nil, r)
		return f(id)
	}
	f, _ := utils.GetTranslationsBySystemLocale()
	return f(id)
}

func InitPlugins() {
	plugins := map[string]plugin.Plugin{
		"jira":       &jira.Plugin{},
		"ldapextras": &ldapextras.Plugin{},
	}
	for id, p := range plugins {
		l4g.Info("Initializing plugin: " + id)
		api := &PluginAPI{
			id:     id,
			router: Srv.Router.PathPrefix("/plugins/" + id).Subrouter(),
		}
		p.Initialize(api)
	}
	utils.AddConfigListener(func(before, after *model.Config) {
		for _, p := range plugins {
			p.OnConfigurationChange()
		}
	})
	for _, p := range plugins {
		p.OnConfigurationChange()
	}
}
