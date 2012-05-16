var Athlete = {};

/**
 * Client for making requests to the Athlete.com API.
 * Currently it just helps with request signatures.
 * Use it like this:
 *
 *   var publicKey = 'mypublickey',
 *       privateKey = 'myprivatekey',
 *
 *   var client = AthleteAPIClient({
 *       publicKey: 'mypublickey',
 *       privateKey: 'myprivatekey',
 *       endpoint: 'http://www.athlete.com'
 *   });
 *   
 *   var url = client.sign('/api/v1/users/5/', 'get');
 *   doAjaxStuff(url)
 *
 * Depends on CryptoJS 3 (https://code.google.com/p/crypto-js/).
 * Only hmac-sha256.js is needed and it is distributed with this client.
 */
Athlete.APIClient = function(options) {
    this.endpoint = this.options.endpoint;
    this.publicKey = this.options.publicKey;
    this.privateKey = this.options.privateKey;
};
Athlete.ApiClient.prototype = {
    /**
     * Implements request signing as specified here:
     * http://readthedocs.org/docs/athletecom-api/en/latest/getting_started/authentication.html#client-authentication
     */
    sign: function(path, method, qsParams) {
        qsParams = qsParams || {};

        qsParams.public_key = this.publicKey;
        qsParams.timestemp = this._formatDateISO8601(new Date());

        var stringToSign = [
            method.toUpperCase(),
            path,
            this._serializeParams(qsParams)
        ].join("\n");

        qsParams.signature = this._digest(privateKey, stringToSign);

        return this.endpoint + path + '?' + this._serializeparams(qsParams);
    },

    /**
     * Formats a Date object according to ISO 8601.
     * The output will look something like this:
     * 2009-09-28T19:03:12Z
     */
    _formatDateISO8601: function(d) {
        function pad(n){return n<10 ? '0'+n : n}
        return d.getUTCFullYear()+'-'
            + pad(d.getUTCMonth()+1)+'-'
            + pad(d.getUTCDate())+'T'
            + pad(d.getUTCHours())+':'
            + pad(d.getUTCMinutes())+':'
            + pad(d.getUTCSeconds())+'Z';
    },

    /**
     * Creates a signature w/ a private key and message using HMAC with SHA256.
     */
    _digest: function(key, msg) {
        if (typeof(CryptoJS) === 'undefined' || typeof(CryptoJS.HmacSHA256) === 'undefined') {
            throw "Can't find CryptoJS.HmacSHA256. Perhaps you didn't load it.";
        }
        var hash = CryptoJS.HmacSHA256(msg, key);
        return hash.toString(CryptoJS.enc.Base64);
    }
};
