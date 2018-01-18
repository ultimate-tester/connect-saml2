#!/usr/bin/env node

var fs = require('fs');
var express = require("express");
var morgan = require("morgan");
var cookieParser = require("cookie-parser");
var session = require("express-session");
var express_saml2 = require("./");

var app = express();

app.use(morgan('combined'));
app.use(cookieParser());
app.use(session({secret: "secret"}));

app.use(connect_saml2({
  ensureAuthentication: true,
  idp: {
    singleSignOnService: "https://openidp.feide.no/simplesaml/saml2/idp/SSOService.php",
    fingerprint: "C9:ED:4D:FB:07:CA:F1:3F:C2:1E:0F:EC:15:72:04:7E:B8:A7:A4:CB",
  },
  sp: {
    entityId: "fknsrsbiz-testing",
  },
}));

app.use(function(req, res, next) {
  return res.end(JSON.stringify(req.user, null, 2));
});

app.listen(3000, function() {
  console.log("listening");
});
