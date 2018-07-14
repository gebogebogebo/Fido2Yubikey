function checkFirst(){
    if (PublicKeyCredential)
    {
        alert("PublicKeyCredential-対応!");
    }else{
         /* Platform not capable. Handle error. */
         alert("PublicKeyCredential-未対応です");
    }
}

function createYubikey(){
    
    var options = {
        rp: {
            id: location.host,
            name: location.host,
        },
        user: {
            id: new Uint8Array([129, 230, 232]),
            name: "gebo",
            displayName: "gebo",
        },
        challenge: window.crypto.getRandomValues(new Uint8Array(32)),
        pubKeyCredParams: [
            {
                type: "public-key",
                alg: -7, // cose_alg_ECDSA_w_SHA256,
            },
        ],
    }
    console.log(options);

    // このあと、Yubikeyがピカピカ光るのでタッチするとthenかcatchに入る
    navigator.credentials.create({ "publicKey": options })
        .then(function (credential) {
        //alert("navigator.credentials.create(assertion)-OK");

        //このサンプルでほしいのはcredentialIdだけ
        const {id, rawId, response, type} = credential; // type = "public-key"
        const {attestationObject, clientDataJSON} = response;   
        
        // <attestationObject>
        // attestationObjectをCBORパース
        let attestationObject_json = CBOR.decode(attestationObject);    
        const {attStmt, authData, fmt} = attestationObject_json;
      
        // +------------------------------------------+
        // | RPID hash (32) | Flags (1) | Counter (4) |
        // +------------------------------------------+
        // | authData                                 |
        // +------------------------------------------+
        const rpidHash = authData.slice( 0, 32);
        const flag     = authData.slice(32, 33); //.readUInt8(0)
        const counter  = authData.slice(33, 37); //.readUInt32BE(0)

        // +----------------------------------------+
        // | AAGUID (16)                            |
        // +----------------------------------------+
        // | CredID Len (2) | CredID                |
        // +----------------------------------------+
        // | CredentialPublicKey                    |
        // +----------------------------------------+
        const aaguid              = authData.slice(37, 53)
        const tmp  = authData.slice(53, 55); //.readUInt16BE(0)
        // tmp は Uint8Array[2] これをビッグエンディアンのUint16にする
        var credentialIdLength = (tmp[0] << 8) + tmp[1];
        const credentialId        = authData.slice(55, 55 + credentialIdLength);
        let credentialId_base64 =Uint8ArraytoBase64(credentialId);

        let msg = "credentialId\n";
        msg = msg + credentialId_base64;
        alert(msg);
        
        let text = document.getElementById("credentialId");
        text.innerHTML = credentialId_base64;

        // credentialPublicKey は、さらに COSE という形式でエンコードされているので、エンコードはあきらめる
        //const credentialPublicKey = (await cbor.decodeAll(authData.slice(55 + credentialIdLength))).shift()

        // <clientDataJSON>はほおっておくパースするなら
        // clientDataJSONはBase64→JSON
        //let clientDataJSON_base64 = Uint8ArraytoBase64(clientDataJSON);
        //let clientDataJSON_json = Base64.decode(clientDataJSON_base64);

    }).catch(function (err) {
        let msg = "エラー\n";
        msg = msg + err;
        alert(msg);
    });
    
}

function getYubikey(){
    let text = document.getElementById("credentialId");
    let credentialId = text.innerHTML;

    var options = {
        challenge: window.crypto.getRandomValues(new Uint8Array(32)),
        allowCredentials: [
        {
            type: "public-key",
            id: Base64toUint8Array(credentialId),
        }  
        ],
    }
    console.log(options);

    navigator.credentials.get({ "publicKey": options })
        .then(function (assertion) {
        alert("navigator.credentials.get(assertion)-OK");
    }).catch(function (err) {
        // No acceptable credential or user refused consent. Handle appropriately.
        let msg = "エラー\n";
        msg = msg + err;
        alert(msg);
    });
      
}

function Uint8ArraytoBase64(bin, opt={urlsafe:true}) {
    const uint8array = new Uint8Array(bin)
    // TODO: use {window|util}.TextDecoder
    const str = btoa(String.fromCharCode(...uint8array))
    if (opt.urlsafe) {
      return str
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=/g, "")
    }
    return str
}

function Base64toUint8Array(b64str, opt={urlsafe:true}) {
    if (opt.urlsafe) {
      const len = b64str.length
      b64str = b64str
        .replace(/-/g, "+")
        .replace(/_/g, "/")
        .padEnd(len+((4-len%4)%4), "=")
    }
    return new Uint8Array([...atob(b64str)].map((e) => e.charCodeAt(0)))
  }