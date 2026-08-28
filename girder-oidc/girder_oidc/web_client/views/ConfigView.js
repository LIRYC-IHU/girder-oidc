import ConfigViewTemplate from '../templates/configView.pug';
import '../stylesheets/configView.styl';

const PluginConfigBreadcrumbWidget = girder.views.widgets.PluginConfigBreadcrumbWidget;
const View = girder.views.View;
const { getApiRoot, restRequest } = girder.rest;
const events = girder.events;
const $ = girder.$;

/**
 * Single-screen admin configuration for the OIDC plugin.
 */
var ConfigView = View.extend({
    events: {
        'submit .g-oidc-config-form': function (event) {
            event.preventDefault();
            this.$('#g-oidc-error-message').empty();

            const data = {
                enabled: this.$('.g-oidc-enabled').is(':checked'),
                clientId: this.$('#g-oidc-client-id').val().trim(),
                publicUrl: this.$('#g-oidc-public-url').val().trim(),
                internalUrl: this.$('#g-oidc-internal-url').val().trim(),
                scopes: this.$('#g-oidc-scopes').val().trim(),
                buttonLabel: this.$('#g-oidc-button-label').val().trim(),
                autoCreateUsers: this.$('.g-oidc-auto-create').is(':checked'),
                ignoreRegistrationPolicy: this.$('.g-oidc-ignore-registration').is(':checked'),
                trustUnverifiedEmail: this.$('.g-oidc-trust-unverified-email').is(':checked'),
                adminClaim: this.$('#g-oidc-admin-claim').val().trim(),
                adminClaimValue: this.$('#g-oidc-admin-claim-value').val().trim()
            };
            // Only send the secret when the admin actually typed one.
            const secret = this.$('#g-oidc-client-secret').val();
            if (secret) {
                data.clientSecret = secret;
            }

            restRequest({
                method: 'PUT',
                url: 'oidc/configuration',
                data,
                error: null
            }).done(() => {
                events.trigger('g:alert', {
                    icon: 'ok',
                    text: 'OIDC settings saved.',
                    type: 'success',
                    timeout: 3000
                });
                this.$('#g-oidc-client-secret').val('');
                this.initialize();
            }).fail((resp) => {
                this.$('#g-oidc-error-message').text(
                    (resp.responseJSON && resp.responseJSON.message) || 'Save failed.');
            });
        },
        'click .g-oidc-test': function () {
            const $result = this.$('#g-oidc-test-result');
            const $button = this.$('.g-oidc-test');
            $result.removeClass('g-oidc-test-ok g-oidc-test-fail')
                .text('Testing connection…');
            $button.prop('disabled', true);

            restRequest({
                method: 'POST',
                url: 'oidc/configuration/test',
                data: {
                    publicUrl: this.$('#g-oidc-public-url').val().trim(),
                    internalUrl: this.$('#g-oidc-internal-url').val().trim()
                },
                error: null
            }).done((resp) => {
                if (resp.ok) {
                    $result.addClass('g-oidc-test-ok').empty()
                        .append($('<b>').text('Connection OK. '))
                        .append(document.createTextNode('Issuer: '))
                        .append($('<code>').text(resp.issuer || ''))
                        .append(document.createTextNode(
                            ', ' + resp.jwksKeys + ' signing key(s).'));
                } else {
                    $result.addClass('g-oidc-test-fail').empty()
                        .append($('<b>').text('Connection failed. '))
                        .append(document.createTextNode(resp.message || ''));
                }
            }).fail((resp) => {
                $result.addClass('g-oidc-test-fail').text(
                    (resp.responseJSON && resp.responseJSON.message)
                    || 'Connection test failed.');
            }).always(() => {
                $button.prop('disabled', false);
            });
        }
    },

    initialize: function () {
        restRequest({ method: 'GET', url: 'oidc/configuration' }).done((resp) => {
            this.config = resp;
            this.render();
        });
    },

    render: function () {
        if (!this.config) {
            return this;
        }

        let apiRoot = getApiRoot();
        if (apiRoot.substring(0, 1) !== '/') {
            apiRoot = '/' + apiRoot;
        }
        const origin = window.location.protocol + '//' + window.location.host;

        this.$el.html(ConfigViewTemplate({
            config: this.config,
            redirectUri: `${origin}${apiRoot}/oidc/callback`
        }));

        if (!this.breadcrumb) {
            this.breadcrumb = new PluginConfigBreadcrumbWidget({
                pluginName: 'OIDC Login',
                el: this.$('.g-config-breadcrumb-container'),
                parentView: this
            }).render();
        }

        return this;
    }
});

export default ConfigView;
