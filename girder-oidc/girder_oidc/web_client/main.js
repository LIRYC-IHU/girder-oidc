import './routes';

// Extends and overrides core views.
import './views/LoginView';
import './views/UserAccountView';

// A `girderOidcCode` query param means we were just redirected back from a
// successful OIDC login. The code is a single-use, 60-second handle on the
// session token -- never the token itself, which must not end up in browser
// history or in the access logs of anything sitting in front of Girder.
const oidcCode = new URLSearchParams(window.location.search).get('girderOidcCode');

if (oidcCode) {
    // Drop the code from the visible URL before doing anything else, so a
    // bookmark or a shared link can't carry it. replaceState edits the current
    // history entry in place rather than pushing a new one.
    const cleanUrl = new URL(window.location.href);
    cleanUrl.searchParams.delete('girderOidcCode');
    window.history.replaceState(null, '', cleanUrl.toString());

    // The exchange has to wait for the API root. Girder loads plugin bundles
    // *before* it calls `initializeDefaultApp`, which is what sets the root, so
    // requesting at import time would post to `/undefined/oidc/exchange`.
    // `g:appload.before` fires immediately after `setApiRoot` and before the
    // rest of the bootstrap, which makes it the earliest point where
    // `restRequest` resolves to a real URL.
    girder.events.once('g:appload.before', () => {
        girder.rest.restRequest({
            method: 'POST',
            url: 'oidc/exchange',
            data: { code: oidcCode },
            error: null
        }).done((resp) => {
            window.localStorage.setItem('girderToken', resp.token);
            girder.auth.setCurrentToken(resp.token);
            // Reload so girder bootstraps with the token in hand: the app is
            // already coming up anonymously behind this request. `replace`
            // keeps the (already cleaned) URL as the current history entry
            // instead of adding one.
            window.location.replace(cleanUrl.toString());
        }).fail(() => {
            girder.events.trigger('g:alert', {
                icon: 'cancel',
                text: 'Could not complete the single sign-on login. Please try again.',
                type: 'danger',
                timeout: 5000
            });
        });
    });
}
