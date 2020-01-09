/*----------------------------------------------------
 * 登録
 *--------------------------------------------------*/

async function registerAsync() {
    // ※サンプルコードでは、WebAuthn API対応判定を追加
    if (!window.PublicKeyCredential) {
        alert("未対応のブラウザです");
        return;
    }

    try {
        // RPサーバから公開鍵クレデンシャル生成オプションを取得
        const optionsRes = await postAttestationOptions();
        const optionsJSON = await optionsRes.json();
        // 認証器からアテステーションレスポンスを取得
        const credential = await createCredential(optionsJSON);
        // RPサーバにアテステーションレスポンスを送信
        const response = await registerFinish(credential);
        // ログインページへ移動
        redirectToSignInPage(response);
    } catch (error) {
        alert(error);
    }
}

function postAttestationOptions() {
    const url = '/attestation/options';
    const data = {
        'email': document.getElementById('email').value,
        'displayName': document.getElementById('displayName').value,
    };

    return fetch(url, {
        method: 'POST',
        body: JSON.stringify(data),
        headers: {
            'Content-Type': 'application/json'
        }
    });
}

function createCredential(options) {
    // ArrayBufferに変換
    options.challenge = base64ToArrayBuffer(options.challenge.value);
    options.user.id = base64ToArrayBuffer(options.user.id);
    options.excludeCredentials =
        options.excludeCredentials
            .map(credential => Object.assign({},
                credential, {
                    id: base64ToArrayBuffer(credential.id),
                }));

    // 認証器からアテステーションレスポンスを取得するWebAuthn API
    return navigator.credentials.create({
        publicKey: options,
    });
}

function registerFinish(credential) {
    const url = '/attestation/result';
    const data = {
        'clientDataJSON': arrayBufferToBase64(credential.response.clientDataJSON),
        'attestationObject': arrayBufferToBase64(credential.response.attestationObject),
    };
    return fetch(url, {
        method: 'POST',
        body: JSON.stringify(data),
        cache: "no-cache",
        headers: {
            'Content-Type': 'application/json'
        }
    });
}

function redirectToSignInPage(response) {
    if (response.ok) {
        alert('登録しました');
        location.href = 'signin.html'
    } else {
        alert(response);
    }
}



/*----------------------------------------------------
 * 認証
 *--------------------------------------------------*/

async function authenticationAsync() {
    // ※サンプルコードでは、WebAuthn API対応判定を追加
    if (!window.PublicKeyCredential) {
        alert("未対応のブラウザです");
        return;
    }

    try {
        // RPサーバから公開鍵クレデンシャル要求オプションを取得
        const optionsRes = await postAssertionOptions();
        const optionsJSON = await optionsRes.json();
        // 認証器からアサーションレスポンスを取得
        const assertion = await getAssertion(optionsJSON);
        // RPサーバにアサーションレスポンスを送信
        const response = await authenticationFinish(assertion);
        signedIn(response);
    } catch (error) {
        alert(error);
    }
}

function postAssertionOptions() {
    const url = '/assertion/options';
    const data = {
        'email': document.getElementById('email').value
    };

    return fetch(url, {
        method: 'POST',
        body: JSON.stringify(data),
        headers: {
            'Content-Type': 'application/json'
        }
    });
}

function getAssertion(options) {
    // ArrayBufferに変換
    options.challenge = base64ToArrayBuffer(options.challenge.value);
    options.allowCredentials = options.allowCredentials
        .map(credential => Object.assign({},
            credential, {
                id: base64ToArrayBuffer(credential.id),
            }));

    // 認証器からアサーションレスポンスを取得するWebAuthn API
    return navigator.credentials.get({
        'publicKey': options
    });
}

function authenticationFinish(assertion) {
    const url = '/assertion/result';
    const data = {
        'credentialId': arrayBufferToBase64(assertion.rawId),
        'clientDataJSON': arrayBufferToBase64(assertion.response.clientDataJSON),
        'authenticatorData': arrayBufferToBase64(assertion.response.authenticatorData),
        'signature': arrayBufferToBase64(assertion.response.signature),
        'userHandle': arrayBufferToBase64(assertion.response.userHandle),
    };
    return fetch(url, {
        method: 'POST',
        body: JSON.stringify(data),
        headers: {
            'Content-Type': 'application/json'
        }
    });
}

function signedIn(response) {
    if (response.ok) {
        alert('ログインしました');
    } else {
        alert(response);
    }
}



/*----------------------------------------------------
 * 共通
 *--------------------------------------------------*/

// Base64文字列をArrayBufferにデコード
function base64ToArrayBuffer(base64String) {
    return Uint8Array.from(atob(base64String), c => c.charCodeAt(0));
}

// ArrayBufferをBase64文字列にエンコード
function arrayBufferToBase64(arrayBuffer) {
    return btoa(String.fromCharCode(...new Uint8Array(arrayBuffer)));
}
