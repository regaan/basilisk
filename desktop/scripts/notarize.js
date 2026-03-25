const path = require('path');
const { notarize } = require('@electron/notarize');

exports.default = async function notarizeApp(context) {
    if (context.electronPlatformName !== 'darwin') {
        return;
    }

    const appPath = path.join(context.appOutDir, `${context.packager.appInfo.productFilename}.app`);
    const teamId = process.env.APPLE_TEAM_ID;
    if (!teamId) {
        console.log('[notarize] APPLE_TEAM_ID not configured, skipping notarization.');
        return;
    }

    const apiKey = process.env.APPLE_API_KEY;
    const apiKeyId = process.env.APPLE_API_KEY_ID;
    const apiIssuer = process.env.APPLE_API_ISSUER;
    if (apiKey && apiKeyId && apiIssuer) {
        console.log(`[notarize] Submitting ${appPath} using App Store Connect API key.`);
        await notarize({
            appPath,
            appleApiKey: apiKey,
            appleApiKeyId: apiKeyId,
            appleApiIssuer: apiIssuer,
            teamId,
        });
        return;
    }

    const appleId = process.env.APPLE_ID;
    const appleIdPassword = process.env.APPLE_APP_SPECIFIC_PASSWORD;
    if (appleId && appleIdPassword) {
        console.log(`[notarize] Submitting ${appPath} using Apple ID credentials.`);
        await notarize({
            appPath,
            appleId,
            appleIdPassword,
            teamId,
        });
        return;
    }

    console.log('[notarize] Apple notarization credentials not configured, skipping notarization.');
};
