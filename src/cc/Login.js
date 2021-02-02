import { useState, useEffect, useCallback } from 'react';
import styled from '@emotion/styled';
import { Component } from '@k8slens/extensions';
import { layout } from './styles';
import { Section } from './Section';
import { useExtState } from './store/ExtStateProvider';
import { useConfig } from './store/ConfigProvider';
import { useBasicAuth } from './store/BasicAuthProvider';
import { useSsoAuth } from './store/SsoAuthProvider';
import { useClusterData } from './store/ClusterDataProvider';
import { useClusterLoadingState } from './hooks/useClusterLoadingState';
import { normalizeUrl } from './netUtil';
import * as strings from '../strings';

const urlClassName = 'lecc-Login--url';

const Field = styled.div(function () {
  return {
    display: 'flex',
    alignItems: 'center',
    marginBottom: layout.gap,

    ':last-child': {
      marginBottom: 0,
    },

    [`div.Input.${urlClassName}`]: {
      flex: 1,
    },

    '> label': {
      minWidth: layout.grid * 23,
      marginRight: `${layout.pad}px`,
    },
  };
});

const Message = styled.div(function () {
  return {
    display: 'flex',

    p: {
      marginTop: 2,
      marginLeft: 3,
    },
  };
});

export const Login = function () {
  //
  // STATE
  //

  const {
    state: {
      authAccess,
      prefs: { cloudUrl },
    },
    actions: extActions,
  } = useExtState();

  const {
    state: {
      loading: configLoading,
      loaded: configLoaded,
      error: configError,
      config,
    },
    actions: configActions,
  } = useConfig();

  const {
    state: { loading: basicAuthLoading },
    actions: basicAuthActions,
  } = useBasicAuth();

  const {
    state: { loading: ssoAuthLoading },
    actions: ssoAuthActions,
  } = useSsoAuth();

  const {
    state: { loaded: clusterDataLoaded, error: clusterDataError },
    actions: clusterDataActions,
  } = useClusterData();

  // NOTE: while this does include the individual flags above, it may include
  //  others we don't need to know details about here, but still need to be
  //  responsive to
  const loading = useClusterLoadingState();

  const [url, setUrl] = useState(cloudUrl || '');
  const [username, setUsername] = useState(authAccess.username || '');
  const [password, setPassword] = useState(authAccess.password || '');
  const [basicValid, setBasicValid] = useState(false); // if basic auth fields are valid

  // {boolean} true if user has clicked the Access button; false otherwise
  const [accessClicked, setAccessClicked] = useState(false);

  const usesSso = !!config?.keycloakLogin;

  //
  // EVENTS
  //

  const startLogin = useCallback(
    function () {
      authAccess.resetCredentials();
      authAccess.resetTokens();
      authAccess.usesSso = usesSso;

      if (!usesSso) {
        authAccess.username = username;
        authAccess.password = password;
      }

      // capture changes to auth details so far, and trigger basic or SSO login in
      //  useClusterLoader() effect (because this will result in an updated authAccess
      //  object that has the right configuration per updates above)
      extActions.setAuthAccess(authAccess);
    },
    [authAccess, extActions, usesSso, username, password]
  );

  const handleUrlChange = function (value) {
    setUrl(value);
  };

  const handleUsernameChange = function (value) {
    setUsername(value);
  };

  const handlePasswordChange = function (value) {
    setPassword(value);
  };

  const handleAccessClick = function () {
    const normUrl = normalizeUrl(url);
    setUrl(normUrl); // update to actual URL we'll use
    setAccessClicked(true);

    basicAuthActions.reset();
    ssoAuthActions.reset();
    clusterDataActions.reset();

    // we're accessing a different instance, so nothing we may have already will
    //  work there
    setUsername('');
    setPassword('');
    authAccess.resetCredentials();
    authAccess.resetTokens();
    extActions.setAuthAccess(authAccess);

    // save URL as `cloudUrl` in preferences since the user claims it's valid
    extActions.setCloudUrl(normUrl);

    // NOTE: if the config loads successfully and we see that the instance is
    //  set for SSO auth, our effect() below that checks for `configLoaded`
    //  will auto-trigger onLogin(), which will then trigger SSO auth
    configActions.load(normUrl); // implicit reset of current config, if any
  };

  const handleLoginClick = function () {
    if (
      clusterDataLoaded &&
      !clusterDataError &&
      url === cloudUrl &&
      authAccess.isValid() &&
      username === authAccess.username &&
      (authAccess.usesSso || password === authAccess.password)
    ) {
      // DEBUG TODO: test this use case under SSO
      // just do a cluster data refresh instead of going through auth again
      clusterDataActions.load({ cloudUrl, config, authAccess });
    } else {
      // no cluster data, or something auth-related has changed: do a full
      //  re-auth and cluster reload
      basicAuthActions.reset();
      ssoAuthActions.reset();
      clusterDataActions.reset();
      startLogin();
    }
  };

  //
  // EFFECTS
  //

  useEffect(
    function () {
      setBasicValid(!!(url && username && password));
    },
    [username, password, url]
  );

  // on load, if we already have an instance URL but haven't yet loaded the config,
  //  load it immediately so we can show the username/password fields right away
  //  and save the user a 'click & wait' if the instance uses basic auth
  useEffect(
    function () {
      if (cloudUrl && !configLoading && !configLoaded) {
        configActions.load(cloudUrl);
      }
    },
    [cloudUrl, configLoading, configLoaded, configActions]
  );

  useEffect(
    function () {
      if (configLoaded && !configError && accessClicked) {
        setAccessClicked(false);

        // start the SSO login process if the instance uses SSO since the user has
        //  clicked on the Access button indicating intent to take action
        if (usesSso) {
          startLogin();
        }
      }
    },
    [
      configLoaded,
      configError,
      config,
      url,
      extActions,
      startLogin,
      accessClicked,
      usesSso,
    ]
  );

  //
  // RENDER
  //

  return (
    <Section className="lecc-Login">
      <h3>{strings.login.title()}</h3>
      <Field>
        <label htmlFor="lecc-login-url">{strings.login.url.label()}</label>
        <Component.Input
          type="text"
          className={urlClassName}
          theme="round-black" // borders on all sides, rounded corners
          id="lecc-login-url"
          disabled={loading}
          value={url}
          onChange={handleUrlChange}
        />
      </Field>
      {(!configLoaded || configError || url !== cloudUrl || usesSso) && (
        <div>
          <Component.Button
            primary
            disabled={loading}
            label={strings.login.action.access()}
            waiting={configLoading}
            onClick={handleAccessClick}
          />
        </div>
      )}
      {configLoaded && !configError && url === cloudUrl && !usesSso && (
        <>
          <Message>
            <Component.Icon material="info" />
            <p>{strings.login.basic.message()}</p>
          </Message>
          <Field>
            <label htmlFor="lecc-login-username">
              {strings.login.username.label()}
            </label>
            <Component.Input
              type="text"
              theme="round-black" // borders on all sides, rounded corners
              id="lecc-login-username"
              disabled={loading}
              value={username}
              onChange={handleUsernameChange}
            />
          </Field>
          <Field>
            <label htmlFor="lecc-login-password">
              {strings.login.password.label()}
            </label>
            <Component.Input
              type="password"
              theme="round-black" // borders on all sides, rounded corners
              id="lecc-login-password"
              disabled={loading}
              value={password}
              onChange={handlePasswordChange}
            />
          </Field>
          <div>
            <Component.Button
              primary
              disabled={loading || !basicValid}
              label={
                clusterDataLoaded && !clusterDataError
                  ? strings.login.action.refresh()
                  : strings.login.action.login()
              }
              waiting={basicAuthLoading}
              onClick={handleLoginClick}
            />
          </div>
        </>
      )}
      {ssoAuthLoading && (
        <Message>
          <Component.Icon material="info" />
          <p>{strings.login.sso.message()}</p>
        </Message>
      )}
    </Section>
  );
};
