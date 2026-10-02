<#import "field.ftl" as field>
<#import "footer.ftl" as loginFooter>
<#import "theme-resources.ftl" as themeResourceTags>
<#macro username>
  <#assign label>
    <#if !realm.loginWithEmailAllowed>${msg("username")}<#elseif !realm.registrationEmailAsUsername>${msg("usernameOrEmail")}<#else>${msg("email")}</#if>
  </#assign>
  <@field.group name="username" label=label>
    <div class="${properties.kcInputGroup}">
      <div class="${properties.kcInputGroupItemClass} ${properties.kcFill}">
        <span class="${properties.kcInputClass} ${properties.kcFormReadOnlyClass}">
          <input id="kc-attempted-username" value="${auth.attemptedUsername}" readonly>
        </span>
      </div>
      <div class="${properties.kcInputGroupItemClass}">
        <button id="reset-login" class="${properties.kcFormPasswordVisibilityButtonClass} kc-login-tooltip" type="button" 
              aria-label="${msg('restartLoginTooltip')}" onclick="location.href='${url.loginRestartFlowUrl}'">
            <i class="fa-sync-alt fas" aria-hidden="true"></i>
            <span class="kc-tooltip-text">${msg("restartLoginTooltip")}</span>
        </button>
      </div>
    </div>
  </@field.group>
</#macro>

<#-- CloakTail sandbox: which guide a page shows. -->
<#function ctGuide id>
  <#if ["login.ftl", "login-username.ftl", "login-password.ftl", "select-authenticator.ftl", "login-otp.ftl", "webauthn-authenticate.ftl", "login-recovery-authn-code-input.ftl", "login-passkeys-conditional-authenticate.ftl"]?seq_contains(id)><#return "Login"></#if>
  <#if id == "register.ftl"><#return "Register"></#if>
  <#if id == "login-reset-password.ftl"><#return "Reset"></#if>
  <#if ["login-update-password.ftl", "login-update-profile.ftl", "update-user-profile.ftl", "update-email.ftl", "login-config-totp.ftl", "terms.ftl", "webauthn-register.ftl", "login-recovery-authn-code-config.ftl", "idp-review-user-profile.ftl"]?seq_contains(id)><#return "Action"></#if>
  <#if ["error.ftl", "webauthn-error.ftl", "login-page-expired.ftl"]?seq_contains(id)><#return "Error"></#if>
  <#return "Default">
</#function>

<#function ctStepCount guide>
  <#return ({"Login": 3, "Register": 3, "Reset": 2, "Action": 2, "Error": 2}[guide])!1>
</#function>

<#macro ctLogo>
  <svg class="ct-logo" viewBox="0 0 32 32" width="28" height="28" aria-hidden="true" focusable="false">
    <defs>
      <linearGradient id="ct-logo-g" x1="0" y1="0" x2="1" y2="1">
        <stop offset="0" stop-color="#60a5fa"/><stop offset="1" stop-color="#2563eb"/>
      </linearGradient>
    </defs>
    <rect width="32" height="32" rx="8" fill="url(#ct-logo-g)"/>
    <path d="M21.5 10.2a8 8 0 1 0 0 11.6" fill="none" stroke="#fff" stroke-width="3" stroke-linecap="round"/>
    <circle cx="22.4" cy="16" r="2.2" fill="#fff"/>
  </svg>
</#macro>

<#macro registrationLayout bodyClass="" displayInfo=false displayMessage=true displayRequiredFields=false>
<!DOCTYPE html>
<html class="${properties.kcHtmlClass!}" lang="${lang}"<#if realm.internationalizationEnabled> dir="${(locale.rtl)?then('rtl','ltr')}"</#if>>

<head>
    <meta charset="utf-8">
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <meta name="color-scheme" content="dark">
    <meta name="theme-color" content="#071330">
    <meta name="viewport" content="width=device-width, initial-scale=1">

    <#if properties.meta?has_content>
        <#list properties.meta?split(' ') as meta>
            <meta name="${meta?split('==')[0]}" content="${meta?split('==')[1]}"/>
        </#list>
    </#if>
    <title>${title!}</title>
    <#if themeResources?? && themeResources.favicons?has_content>
        <@themeResourceTags.renderFavicons themeResources.favicons url.resourcesPath />
    <#else>
        <link rel="icon" href="${url.resourcesPath}/img/favicon.ico" />
    </#if>
    <#if themeResources?? && themeResources.stylesCommon?has_content>
        <@themeResourceTags.renderStyles themeResources.stylesCommon url.resourcesCommonPath />
    <#elseif properties.stylesCommon?has_content>
        <#list properties.stylesCommon?split(' ') as style>
            <link href="${url.resourcesCommonPath}/${style}" rel="stylesheet" />
        </#list>
    </#if>
    <#if themeResources?? && themeResources.styles?has_content>
        <@themeResourceTags.renderStyles themeResources.styles url.resourcesPath />
    <#elseif properties.styles?has_content>
        <#list properties.styles?split(' ') as style>
            <link href="${url.resourcesPath}/${style}" rel="stylesheet" />
        </#list>
    </#if>
    <script type="importmap">
        {
            "imports": {
                "rfc4648": "${url.resourcesCommonPath}/vendor/rfc4648/rfc4648.js"
            }
        }
    </script>
    <#if darkMode>
      <script type="module" async blocking="render">
          <#outputformat "JavaScript">
          const DARK_MODE_CLASS = ${properties.kcDarkModeClass?c};
          const mediaQuery = window.matchMedia("(prefers-color-scheme: dark)");

          updateDarkMode(mediaQuery.matches);
          mediaQuery.addEventListener("change", (event) => updateDarkMode(event.matches));

          function updateDarkMode(isEnabled) {
            const { classList } = document.documentElement;

            if (isEnabled) {
              classList.add(DARK_MODE_CLASS);
            } else {
              classList.remove(DARK_MODE_CLASS);
            }
          }
          </#outputformat>
      </script>
    </#if>
    <#if themeResources?? && themeResources.scripts?has_content>
        <@themeResourceTags.renderScripts themeResources.scripts url.resourcesPath "text/javascript" />
    <#elseif properties.scripts?has_content>
        <#list properties.scripts?split(' ') as script>
            <script src="${url.resourcesPath}/${script}" type="text/javascript"></script>
        </#list>
    </#if>
    <#if scripts??>
        <#list scripts as script>
            <script src="${script}" type="text/javascript"></script>
        </#list>
    </#if>
    <script type="module" src="${url.resourcesPath}/js/passwordVisibility.js"></script>
    <script type="module">
        <#outputformat "JavaScript">
        import { startSessionPolling } from ${(url.resourcesPath + "/js/authChecker.js")?c};

        startSessionPolling(
            ${url.ssoLoginInOtherTabsUrl?c}
        );
        </#outputformat>
    </script>
    <script type="module">
        document.addEventListener("click", (event) => {
            const link = event.target.closest("a[data-once-link]");

            if (!link) {
                return;
            }

            if (link.getAttribute("aria-disabled") === "true") {
                event.preventDefault();
                return;
            }

            const { disabledClass } = link.dataset;

            if (disabledClass) {
                link.classList.add(...disabledClass.trim().split(/\s+/));
            }

            link.setAttribute("role", "link");
            link.setAttribute("aria-disabled", "true");
        });
    </script>
    <#if authenticationSession??>
        <script type="module">
             <#outputformat "JavaScript">
            import { checkAuthSession } from ${(url.resourcesPath + "/js/authChecker.js")?c};

            checkAuthSession(
                ${authenticationSession.authSessionIdHash?c}
            );
            </#outputformat>
        </script>
    </#if>
    <script>
      // Workaround for https://bugzilla.mozilla.org/show_bug.cgi?id=1404468
      const isFirefox = true;
    </script>
</head>

<#assign ctGuideName = ctGuide(pageId)>
<#assign ctAppName = "">
<#if client?? && client.name?has_content><#assign ctAppName = advancedMsg(client.name)><#elseif client?? && client.clientId?has_content><#assign ctAppName = client.clientId></#if>
<body id="keycloak-bg" class="${properties.kcBodyClass!} ct-body" data-page-id="login-${pageId}">
<a class="ct-skip" href="#ct-main">${msg("ctSkip")}</a>
<div class="ct-shell">
  <header class="ct-topbar" id="kc-header">
    <div class="ct-brand">
      <@ctLogo/>
      <span class="ct-brand-name">${msg("ctBrand")}</span>
      <span class="ct-pill">${msg("ctSandbox")}</span>
    </div>
    <div class="ct-realm" title="${msg("ctRealm")}">
      <span class="ct-realm-label">${msg("ctRealm")}</span>
      <code>${realm.name}</code>
    </div>
  </header>

  <div class="ct-layout">
    <section class="ct-intro" aria-labelledby="ct-intro-title">
      <h2 id="ct-intro-title" class="ct-intro-title">${msg("ctIntroTitle")}</h2>
      <p class="ct-intro-text">${msg("ctIntroText")}</p>
      <#if ctAppName?has_content>
        <p class="ct-app"><span>${msg("ctSignInTo")}</span> <strong>${ctAppName}</strong></p>
      </#if>

      <h3 class="ct-steps-title">${msg("ctStepsTitle")}</h3>
      <ol class="ct-steps">
        <#list 1..ctStepCount(ctGuideName) as n>
          <li class="ct-step">
            <span class="ct-step-num" aria-hidden="true">${n}</span>
            <div>
              <p class="ct-step-title">${msg("ct" + ctGuideName + n + "Title")}</p>
              <p class="ct-step-text">${msg("ct" + ctGuideName + n + "Text")}</p>
            </div>
          </li>
        </#list>
      </ol>
      <#if (properties.cloaktailUrl!"")?has_content>
        <p class="ct-links">
          <a href="${(properties.cloaktailUrl!"")}<#if ctGuideName == "Error">/troubleshooting</#if>" target="_blank" rel="noopener">${msg("ctOpenCloakTail")} <span aria-hidden="true">↗</span></a>
        </p>
      </#if>
    </section>

    <aside class="ct-disclaimer" role="note" aria-labelledby="ct-disclaimer-title">
      <svg class="ct-disclaimer-icon" viewBox="0 0 24 24" width="22" height="22" aria-hidden="true" focusable="false"><path fill="currentColor" d="M12 2.5c.6 0 1.1.3 1.4.8l9 15.6a1.6 1.6 0 0 1-1.4 2.4H3a1.6 1.6 0 0 1-1.4-2.4l9-15.6c.3-.5.8-.8 1.4-.8Zm0 6a1 1 0 0 0-1 1v4.5a1 1 0 1 0 2 0V9.5a1 1 0 0 0-1-1Zm0 8.2a1.2 1.2 0 1 0 0 2.4 1.2 1.2 0 0 0 0-2.4Z"/></svg>
      <div>
        <p class="ct-disclaimer-title" id="ct-disclaimer-title">${msg("ctDisclaimerTitle")}</p>
        <p class="ct-disclaimer-text">${msg("ctDisclaimerText")}</p>
        <#if (properties.cloaktailUrl!"")?has_content>
          <a class="ct-disclaimer-link" href="${(properties.cloaktailUrl!"")}/disclaimer" target="_blank" rel="noopener">${msg("ctDisclaimerLink")} <span aria-hidden="true">↗</span></a>
        </#if>
      </div>
    </aside>

    <div class="ct-card-wrap">
    <main class="${properties.kcLoginMain!} ct-card" id="ct-main">
      <div class="${properties.kcLoginMainHeader!}">
        <h1 class="${properties.kcLoginMainTitle!}" id="kc-page-title"><#nested "header"></h1>
        <#if realm.internationalizationEnabled  && locale.supported?size gt 1>
        <div class="${properties.kcLoginMainHeaderUtilities!}">
          <div class="${properties.kcInputClass!}">
            <select
              aria-label="${msg("languages")}"
              id="login-select-toggle"
              onchange="if (this.value) window.location.href=this.value"
            >
              <#list locale.supported?sort_by("label") as l>
                <option
                  value="${l.url}"
                  ${(l.languageTag == locale.currentLanguageTag)?then('selected','')}
                >
                  ${l.label}
                </option>
              </#list>
            </select>
            <span class="${properties.kcFormControlUtilClass}">
              <span class="${properties.kcFormControlToggleIcon!}">
                <svg
                  class="pf-v5-svg"
                  viewBox="0 0 320 512"
                  fill="currentColor"
                  aria-hidden="true"
                  role="img"
                  width="1em"
                  height="1em"
                >
                  <path
                    d="M31.3 192h257.3c17.8 0 26.7 21.5 14.1 34.1L174.1 354.8c-7.8 7.8-20.5 7.8-28.3 0L17.2 226.1C4.6 213.5 13.5 192 31.3 192z"
                  >
                  </path>
                </svg>
              </span>
            </span>
          </div>
        </div>
        </#if>
      </div>
      <div class="${properties.kcLoginMainBody!}">
        <#if !(auth?has_content && auth.showUsername() && !auth.showResetCredentials())>
            <#if displayRequiredFields>
                <div class="${properties.kcContentWrapperClass!}">
                    <div class="${properties.kcLabelWrapperClass!} subtitle">
                        <span class="${properties.kcInputHelperTextItemTextClass!}">
                          <span class="${properties.kcInputRequiredClass!}">*</span> ${msg("requiredFields")}
                        </span>
                    </div>
                </div>
            </#if>
        <#else>
            <#if displayRequiredFields>
                <div class="${properties.kcContentWrapperClass!}">
                    <div class="${properties.kcLabelWrapperClass!} subtitle">
                        <span class="${properties.kcInputHelperTextItemTextClass!}">
                          <span class="${properties.kcInputRequiredClass!}">*</span> ${msg("requiredFields")}
                        </span>
                    </div>
                    <div class="${properties.kcFormClass} ${properties.kcContentWrapperClass}">
                        <#nested "show-username">
                        <@username />
                    </div>
                </div>
            <#else>
                <div class="${properties.kcFormClass} ${properties.kcContentWrapperClass}">
                  <#nested "show-username">
                  <@username />
                </div>
            </#if>
        </#if>

        <#-- App-initiated actions should not see warning messages about the need to complete the action -->
        <#-- during login.                                                                               -->
        <#if displayMessage && message?has_content && (message.type != 'warning' || !isAppInitiatedAction??)>
            <div class="${properties.kcAlertClass!} pf-m-${(message.type = 'error')?then('danger', message.type)}">
                <div class="${properties.kcAlertIconClass!}">
                    <#if message.type = 'success'><span class="${properties.kcFeedbackSuccessIcon!}"></span></#if>
                    <#if message.type = 'warning'><span class="${properties.kcFeedbackWarningIcon!}"></span></#if>
                    <#if message.type = 'error'><span class="${properties.kcFeedbackErrorIcon!}"></span></#if>
                    <#if message.type = 'info'><span class="${properties.kcFeedbackInfoIcon!}"></span></#if>
                </div>
                <span class="${properties.kcAlertTitleClass!} kc-feedback-text">${message.summary}</span>
            </div>
        </#if>

        <#if pageId == "register.ftl">
            <div class="ct-inline-notice" role="note">
                <svg viewBox="0 0 20 20" width="18" height="18" aria-hidden="true" focusable="false"><path fill="currentColor" d="M10 2a8 8 0 1 0 0 16 8 8 0 0 0 0-16Zm0 3.5a1 1 0 0 1 1 1V10a1 1 0 1 1-2 0V6.5a1 1 0 0 1 1-1Zm0 7a1.1 1.1 0 1 1 0 2.2 1.1 1.1 0 0 1 0-2.2Z"/></svg>
                <span>${msg("ctRegisterNotice")}</span>
            </div>
        </#if>

        <#nested "form">

        <#if auth?has_content && auth.showTryAnotherWayLink()>
          <form id="kc-select-try-another-way-form" action="${url.loginAction}" method="post" novalidate="novalidate">
              <input type="hidden" name="tryAnotherWay" value="on"/>
              <a id="try-another-way" href="javascript:document.forms['kc-select-try-another-way-form'].requestSubmit()"
                  class="${properties.kcButtonSecondaryClass} ${properties.kcButtonBlockClass} ${properties.kcMarginTopClass}">
                    ${msg("doTryAnotherWay")}
              </a>
          </form>
        </#if>

        <#if switchOrganizationEnabled?? && switchOrganizationEnabled>
          <form id="kc-switch-organization-form" action="${url.loginAction}" method="post" novalidate="novalidate">
              <input type="hidden" name="switchOrganization" value="true"/>
              <a id="switch-organization" href="javascript:document.forms['kc-switch-organization-form'].requestSubmit()"
                  class="${properties.kcButtonSecondaryClass} ${properties.kcButtonBlockClass} ${properties.kcMarginTopClass}">
                    ${msg("doSwitchOrganization")}
              </a>
          </form>
        </#if>

          <div class="${properties.kcLoginMainFooter!}">
              <#nested "socialProviders">

              <#if displayInfo>
                  <div id="kc-info" class="${properties.kcLoginMainFooterBand!} ${properties.kcFormClass}">
                      <div id="kc-info-wrapper" class="${properties.kcLoginMainFooterBandItem!}">
                          <#nested "info">
                      </div>
                  </div>
              </#if>
          </div>
      </div>

        <div class="${properties.kcLoginMainFooter!}">
            <@loginFooter.content/>
        </div>
    </main>
    </div>
  </div>

  <footer class="ct-footer">
    <span>${msg("ctBrand")} ${msg("ctSandbox")?lower_case}</span>
    <span aria-hidden="true">·</span>
    <span>${msg("ctTestEnvironment")}</span>
  </footer>
</div>
</body>
</html>
</#macro>
