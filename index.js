const c14n = require("xml-c14n")();
const express = require("express");
const randomId = require("proquint-random-id");
const saml2 = require("saml2");
const url = require("url");
const xmldom = require("xmldom");
const xpath = require("xpath");
const zlib = require("zlib");

const User = require("./lib/user");

const express_saml2 = function (options) {
    options = options || {};

    const urlencoded = express.urlencoded();
    const canonicaliser = c14n.createCanonicaliser('http://www.w3.org/2001/10/xml-exc-c14n#');

    if (!options.idp) {
        throw Error('idp parameters are required');
    }

    if (!options.sp) {
        throw Error('sp parameters are required');
    }

    const idp = new saml2.IdentityProvider(options.idp);
    const sp = new saml2.ServiceProvider(options.sp);

    const ssoConsumerPostPath = options['ssoConsumerPostPath'] || '/SAML2/AssertionConsumer/POST';

    const ensureAuthentication = !!options['ensureAuthentication'];
    const keepSignatures = !!options['keepSignatures'];

    const saveAssertionXml = options['saveAssertionXml'] || function (assertionXml, req, cb) {
        req.session._saml = req.session._saml || {};
        req.session._saml.assertionXml = assertionXml;

        return cb();
    };

    const afterAuthentication = options.afterAuthentication || function (req, cb) {
        req.session._saml = req.session._saml || {};
        req.session._saml.fresh = true;

        return cb();
    };

    const fetchAssertionXml = options['fetchAssertionXml'] || function (req, cb) {
        return cb(null, (req.session && req.session._saml && req.session._saml.assertionXml) || null);
    };

    const removeAssertionXml = options['removeAssertionXml'] || function removeAssertionXml(req, cb) {
        if (req.session && req.session._saml && req.session._saml.assertionXml) {
            delete req.session._saml.assertionXml;
        }

        return cb();
    };

    const saveRelayState = options['saveRelayState'] || function (req, id, relayState, cb) {
        req.session._saml = req.session._saml || {};
        req.session._saml.relayState = req.session._saml.relayState || {};
        req.session._saml.relayState[id] = relayState;

        return cb();
    };

    const fetchRelayState = options['fetchRelayState'] || function (req, id, cb) {
        let relayState = null;

        if (req.session && req.session._saml && req.session._saml.relayState && req.session._saml.relayState[id]) {
            relayState = req.session._saml.relayState[id];

            delete req.session._saml.relayState[id];
        }

        return cb(null, relayState);
    };

    return function (req, res, next) {
        req.removeAssertion = function removeAssertion(done) {
            req.samlAssertion = null;

            return removeAssertionXml(req, done);
        };

        req.initiateAuthentication = function initiateAuthentication() {
            const authnRequest = sp.createAuthnRequest();

            return canonicaliser.canonicalise(authnRequest.toDocument(), function (err, authnRequestXml) {
                if (err) {
                    return next(err);
                }

                return zlib.deflateRaw(authnRequestXml, function (err, authnRequestDeflatedXml) {
                    if (err) {
                        return next(err);
                    }

                    const relayState = {
                        initiationTime: new Date().toISOString(),
                        previousUrl: req.url,
                    };

                    const relayStateId = Date.now() + "-" + randomId();

                    const parameters = {
                        SAMLEncoding: 'urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:DEFLATE',
                        SAMLRequest: authnRequestDeflatedXml.toString('base64'),
                        RelayState: relayStateId,
                    };

                    const uri = url.parse(idp.singleSignOnService, true);

                    for (const k in parameters) {
                        uri.query[k] = parameters[k];
                    }

                    return saveRelayState(req, relayStateId, relayState, function (err) {
                        if (err) {
                            return next(err);
                        }

                        res.writeHead(302, {
                            location: url.format(uri),
                        });

                        return res.end();
                    });
                });
            });
        };

        fetchAssertionXml(req, function (err, storedAssertionXml) {
            if (err) {
                return next(err);
            }

            if (storedAssertionXml) {
                let storedAssertionDocument = null;
                let storedAssertion = null;

                try {
                    storedAssertionDocument = (new xmldom.DOMParser()).parseFromString(storedAssertionXml);
                    storedAssertion = saml2.Protocol.fromDocument(storedAssertionDocument);
                } catch (e) {
                    return next(e);
                }

                const authnStatementElement = xpath.select1("./*[namespace-uri()='urn:oasis:names:tc:SAML:2.0:assertion' and local-name()='Assertion']/*[namespace-uri()='urn:oasis:names:tc:SAML:2.0:assertion' and local-name()='AuthnStatement']", storedAssertionDocument);
                let sessionNotOnOrAfter = null;
                if (authnStatementElement) {
                    sessionNotOnOrAfter = authnStatementElement.getAttribute('SessionNotOnOrAfter');
                }

                req.samlAssertionXml = storedAssertionXml;
                req.samlAssertionDocument = storedAssertionDocument;
                req.samlAssertion = storedAssertion;
                req.user = new User({
                    expiresAt: sessionNotOnOrAfter ? new Date(sessionNotOnOrAfter) : null,
                    id: xpath.select1("./*[namespace-uri()='urn:oasis:names:tc:SAML:2.0:assertion' and local-name()='Assertion']/*[namespace-uri()='urn:oasis:names:tc:SAML:2.0:assertion' and local-name()='Subject']/*[namespace-uri()='urn:oasis:names:tc:SAML:2.0:assertion' and local-name()='NameID']/text()", storedAssertionDocument) + "",
                    attributes: xpath.select("./*[namespace-uri()='urn:oasis:names:tc:SAML:2.0:assertion' and local-name()='Assertion']/*[namespace-uri()='urn:oasis:names:tc:SAML:2.0:assertion' and local-name()='AttributeStatement']/*[namespace-uri()='urn:oasis:names:tc:SAML:2.0:assertion' and local-name()='Attribute']", storedAssertionDocument).map(function (attributeElement) {
                        const attribute = saml2.Protocol.fromDocument(attributeElement);

                        return [
                            attribute.value['name'],
                            attribute.value['attributeValue'].map(function (e) {
                                return e.value;
                            }),
                        ];
                    }).reduce(function (i, v) {
                        i[v[0]] = i[v[0]] || [];
                        i[v[0]] = i[v[0]].concat(v[1]);
                        return i;
                    }, {}),
                });

                if (sessionNotOnOrAfter && new Date(sessionNotOnOrAfter).valueOf() <= Date.now()) {
                    delete req.samlAssertionXml;
                    delete req.samlAssertionDocument;
                    delete req.samlAssertion;
                    delete req.user;
                }
            }

            if (req.url === ssoConsumerPostPath && req.method === 'POST') {
                return urlencoded(req, res, function onParsedBody(err) {
                    if (err) {
                        return next(err);
                    }

                    if (!req.body['SAMLResponse']) {
                        return next(Error("couldn't find SAML response field"));
                    }

                    const samlResponseXml = new Buffer(req.body['SAMLResponse'], "base64").toString();

                    const parser = new xmldom.DOMParser();
                    let samlResponseDocument = null;

                    try {
                        samlResponseDocument = parser.parseFromString(samlResponseXml);
                    } catch (e) {
                        return next(e);
                    }

                    if (samlResponseDocument.documentElement.namespaceURI !== "urn:oasis:names:tc:SAML:2.0:protocol" && samlResponseDocument.documentElement.localName !== "Response") {
                        return next(Error("expected a {urn:oasis:names:tc:SAML:2.0:protocol}Response but got a {" + samlResponseDocument.documentElement.namespaceURI + "}" + samlResponseDocument.documentElement.localName));
                    }

                    return idp.verify(samlResponseDocument, function (err, signatureInfo) {
                        if (err) {
                            return next(err);
                        }

                        const statusElement = xpath.select1("./*[namespace-uri()='urn:oasis:names:tc:SAML:2.0:protocol' and local-name()='Response']/*[namespace-uri()='urn:oasis:names:tc:SAML:2.0:protocol' and local-name()='Status']/*[namespace-uri()='urn:oasis:names:tc:SAML:2.0:protocol' and local-name()='StatusCode']", samlResponseDocument);

                        if (!statusElement) {
                            return next(Error("couldn't find status element in saml response"));
                        }

                        let status = null;
                        try {
                            status = saml2.Protocol.fromDocument(statusElement);
                        } catch (e) {
                            return next(e);
                        }

                        if (status.value !== "urn:oasis:names:tc:SAML:2.0:status:Success") {
                            return next("saml response did not indicate a success status");
                        }

                        const assertionElement = xpath.select1("./*[namespace-uri()='urn:oasis:names:tc:SAML:2.0:protocol' and local-name()='Response']/*[namespace-uri()='urn:oasis:names:tc:SAML:2.0:assertion' and local-name()='Assertion']", samlResponseDocument);

                        if (!assertionElement) {
                            return next(Error("couldn't find assertion in saml response"));
                        }

                        const conditions = xpath.select1("./*[namespace-uri()='urn:oasis:names:tc:SAML:2.0:assertion' and local-name()='Conditions']", assertionElement);
                        if (conditions) {
                            // we don't use the protocol stuff here because it kills our dates

                            const notBefore = conditions.getAttribute("NotBefore"),
                                notOnOrAfter = conditions.getAttribute("NotOnOrAfter");

                            if (notBefore && new Date(notBefore).valueOf() > Date.now()) {
                                return next(Error("NotBefore condition not satisfied"));
                            }

                            if (notOnOrAfter && new Date(notOnOrAfter).valueOf() <= Date.now()) {
                                return next(Error("NotOnOrAfter condition not satisfied"));
                            }
                        }

                        if (!keepSignatures) {
                            // remove signatures from saved assertion unless specified not to
                            const signatures = xpath.select("//*[namespace-uri()='http://www.w3.org/2000/09/xmldsig#' and local-name()='Signature']", assertionElement);

                            for (let i = 0; i < signatures.length; ++i) {
                                if (signatures[i].parentNode) {
                                    signatures[i].parentNode.removeChild(signatures[i]);
                                }
                            }
                        }

                        return canonicaliser.canonicalise(assertionElement, function (err, assertionXml) {
                            if (err) {
                                return next(err);
                            }

                            return saveAssertionXml(assertionXml, req, function (err) {
                                if (err) {
                                    return next(err);
                                }

                                return afterAuthentication(req, function (err) {
                                    if (err) {
                                        return next(err);
                                    }

                                    if (!req.body.RelayState) {
                                        res.writeHead(302, {
                                            location: "/",
                                        });

                                        return res.end();
                                    }

                                    return fetchRelayState(req, req.body.RelayState, function (err, relayState) {
                                        if (err) {
                                            return next(err);
                                        }

                                        if (typeof relayState !== "object" || relayState === null || !relayState.previousUrl) {
                                            res.writeHead(302, {
                                                location: "/",
                                            });

                                            return res.end();
                                        }

                                        res.writeHead(302, {
                                            location: relayState.previousUrl,
                                        });

                                        return res.end();
                                    });
                                });
                            });
                        });
                    });
                });
            }

            if (ensureAuthentication && !req.user) {
                return req.initiateAuthentication();
            }

            return next();
        });
    };
};

module.exports = express_saml2;