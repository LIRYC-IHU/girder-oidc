import './routes';

// Extends and overrides core views.
import './views/LoginView';
import './views/UserAccountView';

// If the URL carries a `girderToken` query param, we were just redirected back
// from a successful OIDC login: persist the token and strip it from the URL.
const girderToken = new URLSearchParams(window.location.search).get('girderToken');

if (girderToken) {
    window.localStorage.setItem('girderToken', girderToken);
    girder.auth.setCurrentToken(girderToken);

    const queryParams = new URLSearchParams(window.location.search);
    queryParams.delete('girderToken');
    window.location.search = queryParams.toString();
}
