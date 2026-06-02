import OidcLoginViewTemplate from '../templates/oidcLoginView.pug';
import '../stylesheets/oidcLoginView.styl';

const View = girder.views.View;
const { restRequest } = girder.rest;

/**
 * Login button injected into the core login modal. Only renders when OIDC is
 * enabled; clicking it starts the authorization-code flow.
 *
 * When OIDC is enabled the classic username/password form (and the
 * register/forgot-password links and Login button) are collapsed by default to
 * steer users toward the OIDC button; a small toggle reveals them.
 */
var OidcLoginView = View.extend({
    events: {
        'click .g-oidc-login-button': function () {
            const redirect = window.location.pathname + window.location.search;
            restRequest({
                url: 'oidc/login',
                data: { redirect }
            }).done((resp) => {
                window.location = resp.url;
            });
        },
        'click .g-oidc-toggle-password': function (event) {
            event.preventDefault();
            this.passwordVisible = !this.passwordVisible;
            this._applyPasswordVisibility();
        }
    },

    initialize: function () {
        this.enabled = false;
        this.buttonLabel = 'Log in with OIDC';
        this.passwordVisible = false;

        restRequest({ url: 'oidc/config' }).done((resp) => {
            this.enabled = !!resp.enabled;
            if (resp.buttonLabel) {
                this.buttonLabel = resp.buttonLabel;
            }
            this.render();
        });
    },

    // The classic-login pieces of the core modal we collapse/reveal. The submit
    // button lives in the modal footer, a sibling of our (modal-body) element.
    _classicElements: function () {
        const $form = this.$el.closest('#g-login-form');
        return this.$('#g-login').closest('.form-group')
            .add(this.$('#g-password').closest('.form-group'))
            .add(this.$('.g-bottom-message'))
            .add($form.find('#g-login-button'));
    },

    _applyPasswordVisibility: function () {
        this._classicElements().toggle(this.passwordVisible);
        this.$('.g-oidc-toggle-icon')
            .toggleClass('icon-right-dir', !this.passwordVisible)
            .toggleClass('icon-down-dir', this.passwordVisible);
        this.$('.g-oidc-toggle-password').attr(
            'title', this.passwordVisible ? 'Hide password login' : 'Show password login');
    },

    render: function () {
        if (!this.enabled) {
            return this;
        }
        this.$el.append(OidcLoginViewTemplate({ buttonLabel: this.buttonLabel }));

        // If password login is disabled server-side there is no classic form to
        // collapse, so drop the toggle entirely.
        if (this.$('#g-login').length === 0) {
            this.$('.g-oidc-toggle-password').remove();
        } else {
            this._applyPasswordVisibility();
        }
        return this;
    }
});

export default OidcLoginView;
