//
// SSO Authentication Provider (Keycloak)
//

import { createContext, useContext, useState, useMemo } from 'react';
import { Util } from '@k8slens/extensions';
import { ProviderStore } from './ProviderStore';
import * as strings from '../../strings';
import { logger } from '../../util';
import { extractJwtPayload } from '../auth/authUtil';
import { AuthClient } from '../auth/clients/AuthClient';

//
// Store
//

class SsoAuthProviderStore extends ProviderStore {
  // basic store is all that is needed for now
}

const pr = new SsoAuthProviderStore();

//
// Internal Methods
//

/**
 * [ASYNC] Start authorization with MCC to get the temp access code via the
 *  redirect URI that will use the 'lens://' protocol to redirect the user
 *  to Lens and ultimately call back into `_completeAuthorization()`.
 * @param {Object} options
 * @param {Object} options.config MCC Config object.
 */
const _startAuthorization = async function ({ config }) {
  pr.reset(true);

  const authClient = new AuthClient({ config });

  if (config.keycloakLogin) {
    // DEBUG TODO: remove state after finished testing; so far, it's not coming back -- see if you get it back in _completeAuthorization(oAuth) object
    const url = authClient.getSsoAuthUrl({ state: 'foo-bar' });
    Util.openExternal(url); // open in default browser
  } else {
    pr.loading = false;
    pr.loaded = true;
    pr.store.error = strings.ssoAuthProvider.errors.basicOnly();
  }

  pr.notifyIfError();
  pr.onChange();
};

/**
 * [ASYNC] Completes the authorization process by exchanging the temp access code
 *  for access tokens.
 *
 * NOTE: This method ASSUMES `loading` is `true` (i.e. load is in progress).
 *
 * @param {Object} options
 * @param {Object} options.oAuth OAuth response data from request for auth code.
 *  See `extEventOauthCodeTs` typeset in `eventBus.ts` for expected shape.
 * @param {Object} options.config MCC Config object.
 * @param {AuthAccess} options.authAccess Current authentication information.
 *  This instance WILL be cleared and updated with new tokens.
 */
const _completeAuthorization = async function ({ oAuth, config, authAccess }) {
  const authClient = new AuthClient({ config });
  let body;
  let error;

  // DEBUG TODO: do we have oAuth.state? why does Keycloak not appear to support this?
  if (oAuth.code) {
    ({ body, error } = await authClient.getToken({ authCode: oAuth.code }));
  } else {
    // no code, something went wrong
    error = oAuth.error || oAuth.error_description || 'unknown';
  }

  pr.loading = false;
  pr.loaded = true;

  if (error) {
    logger.error(
      'SsoAuthProvider._completeAuthorization()',
      `Failed to get tokens from authorization code, error="${error}"`
    );
    pr.store.error = strings.ssoAuthProvider.errors.authCode();
  } else {
    const jwt = extractJwtPayload(body.id_token);
    if (jwt.preferred_username) {
      authAccess.updateTokens(body);
      authAccess.username = jwt.preferred_username;
      authAccess.password = null;
      authAccess.usesSso = true;
    } else {
      logger.error(
        'SsoAuthProvider._completeAuthorization()',
        'Failed to get username from token JWT'
      );
      pr.store.error = strings.ssoAuthProvider.errors.authCode();
    }
  }

  pr.notifyIfError();
  pr.onChange();
};

//
// Provider Definition
//

const SsoAuthContext = createContext();

export const useSsoAuth = function () {
  const context = useContext(SsoAuthContext);
  if (!context) {
    throw new Error('useSsoAuth must be used within an SsoAuthProvider');
  }

  // NOTE: `context` is the value of the `value` prop we set on the
  //  <SsoAuthContext.Provider value={...}/> we return as the <SsoAuthProvider/>
  //  component to wrap all children that should have access to the state (i.e.
  //  all the children that will be able to `useSsoAuth()` to access the state)
  const [state] = context;

  // this is what you actually get from `useSsoAuth()` when you consume it
  return {
    state,

    //// ACTIONS

    actions: {
      /**
       * Begins the authorization process for the Lens app with the MCC server via
       *  user SSO authentication.
       * @param {Object} options
       * @param {Object} options.config MCC Config object.
       */
      startAuthorization(options) {
        if (!pr.loading) {
          // must not be loading (we can only handle one load at a time)
          _startAuthorization(options);
        }
      },

      /**
       * Completes the authorization process given the temporary access code, by
       *  exchanging it for access tokens.
       * @param {Object} options
       * @param {string} code Temporary access code.
       * @param {Object} options.config MCC Config object.
       * @param {AuthAccess} options.authAccess Current authentication information.
       *  This instance WILL be cleared and updated with new tokens.
       */
      completeAuthorization(options) {
        if (pr.loading) {
          // must be loading (i.e. in the middle of the process)
          _completeAuthorization(options);
        }
      },

      /**
       * Imperatively update the loaded state to `true`. Use this if you already
       *  have a valid AuthAccess instance and don't need to authenticate.
       */
      setAuthorized() {
        if (!pr.loading) {
          pr.loaded = true;
          pr.store.error = undefined;
          pr.onChange();
        }
      },

      /** Resets store state. Data will need to be reloaded. */
      reset() {
        if (!pr.loading) {
          pr.reset();
        }
      },
    },
  };
};

export const SsoAuthProvider = function (props) {
  // NOTE: since the state is passed directly (by reference) into the context
  //  returned by the provider, even the initial state should be a clone of the
  //  `store` so that we consistently return a `state` property (in the context)
  //  that is a shallow clone of the `store`
  const [state, setState] = useState(pr.clone());
  const value = useMemo(() => [state, setState], [state]);

  pr.setState = setState;

  return <SsoAuthContext.Provider value={value} {...props} />;
};
