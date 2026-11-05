const HeaderUserView = girder.views.layout.HeaderUserView;
const { wrap } = girder.utilities.PluginUtils;
const { restRequest } = girder.rest;

/**
 * Forward the logout to the identity provider (OpenID Connect RP-Initiated
 * Logout), so that signing out of Girder also ends the provider session rather
 * than leaving one that would silently sign the user straight back in.
 *
 * The provider URL has to be fetched *before* the Girder session is destroyed:
 * it is built from the ID token stored on that session, which
 * `DELETE /user/authentication` deletes. Girder goes first all the same -- if
 * the provider is unreachable the user is still signed out locally, which is
 * the safer way round to fail.
 */
function oidcAwareLogout() {
    const finish = (providerUrl) => {
        girder.auth.logout().done(() => {
            if (providerUrl) {
                // replace(), not assign(): the Back button should not return to
                // a cached page that still looks signed in.
                window.location.replace(providerUrl);
            }
        });
    };

    restRequest({
        method: 'GET',
        url: 'oidc/logout',
        error: null
    }).done((resp) => {
        finish(resp && resp.url);
    }).fail(() => {
        // Propagation off, a local account, no end_session_endpoint, or the
        // provider is down: a Girder-only logout is the right fallback.
        finish(null);
    });
}

wrap(HeaderUserView, 'render', function (render) {
    render.call(this);

    // Girder binds its own logout straight into this view's `events` hash
    // (`'click a.g-logout': logout`), so there is no function to override and
    // no "about to log out" event to listen for. A handler bound directly on
    // the anchor runs in the target phase, ahead of the delegated handler on
    // the view element, and stopImmediatePropagation stops core's from running
    // at all -- which leaves us free to sequence the logout ourselves.
    //
    // Should that markup ever change, this binds nothing and core's logout
    // keeps working untouched: the feature degrades to a Girder-only logout
    // instead of breaking the button.
    this.$('a.g-logout').on('click', (event) => {
        event.preventDefault();
        event.stopImmediatePropagation();
        oidcAwareLogout();
    });

    return this;
});
