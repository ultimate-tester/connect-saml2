#!/usr/bin/env node

const fs = require('fs');
const express = require("express");
const morgan = require("morgan");
const cookieParser = require("cookie-parser");
const session = require("express-session");
const express_saml2 = require("./");

const app = express();

app.use(morgan('combined'));
app.use(cookieParser());
app.use(session({secret: "secret"}));

app.use(express_saml2({
    ensureAuthentication: true,
    idp: {
        singleSignOnService: "https://openidp.feide.no/simplesaml/saml2/idp/SSOService.php",
        fingerprint: "C9:ED:4D:FB:07:CA:F1:3F:C2:1E:0F:EC:15:72:04:7E:B8:A7:A4:CB",
    },
    sp: {
        entityId: "fknsrsbiz-testing",
    },
}));

app.use(function (req, res) {
    return res.end(JSON.stringify(req.user, null, 2));
});

app.listen(3000, function () {
    console.log("listening");
});