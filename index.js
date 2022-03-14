var fs = require('fs');
var fsPromises = fs.promises;
const requestIp = require("request-ip");

const OktaJwtVerifier = require('@okta/jwt-verifier');
const { nextTick } = require('process');

const oktaJwtVerifier = new OktaJwtVerifier({
  issuer: 'https://dev-1043781.okta.com/oauth2/default' // required
});

// function Rule(rule) {
//   this.key = rule.key;
//   this.keyType = rule.keyType;
//   this.decisionType = rule.decisionType;
//   this.value = rule.value;
//   this.desiredOutcome = rule.desiredOutcome;
//   this.evaluate = function (payload) {
//     console.log(this);
//     if (this.decisionType == "equals") {
//       console.log("decisiontype", this.decisionType);
//       console.log(payload[this.key] == this.value);
//       if (!this.desiredOutcome) {
//         console.log("is this being hit");
//         return payload[this.key] == this.value;
//       } else if (payload[this.key] == this.value) {
//         console.log("is this being hit");
//         return this.desiredOutcome;
//       }
//     } else if (this.decisionType == "include") {
//       console.log("is this being hit");
//       if (!this.desiredOutcome) {
//         console.log("is this being hit");
//         return payload[this.key].includes(this.value);
//       } else if (payload[this.key].includes(this.value)) {
//         console.log("is this being hit");
//         return this.desiredOutcome;
//       }
//     }
//   };
// }

function Rule(rule) {
  this.key = rule.key;
  this.keyType = rule.keyType;
  this.decisionType = rule.decisionType;
  this.value = rule.value;
  this.desiredOutcome = rule.desiredOutcome;
  this.rulePathExceptions = rule.pathChips || []
  this.evaluate = function (payload, options = {}) {
    if (this.decisionType == "equals") {
      console.log("is this being hit");
      console.log(payload[this.key] == this.value);
      if (!this.desiredOutcome) {
        console.log("is this being hit");
        return payload[this.key] == this.value;
      } else if (payload[this.key] == this.value) {
        console.log("is this being hit");
        return this.desiredOutcome;
      }
    } else if (this.decisionType == "include") {
      console.log("is this being hit");
      console.log("this is the payload", payload[this.key]);
      if (payload[this.key]) {
        if (!this.desiredOutcome) {
          console.log("includes without desired outcome");
          console.log(payload, this.key);
          console.log(payload[this.key], this.value);
          console.log(payload[this.key].includes(this.value));
          return payload[this.key].includes(this.value);
        } else if (payload[this.key].includes(this.value)) {
          console.log("includes with desired outcome");
          return this.desiredOutcome;
        }
      } else {
        return false;
      }
    } else if (this.decisionType == "match") {
      console.log("in the match type");
      console.log(options)
      try {
        var idToCheck = options.path.split(this.value)[1].split("/")[0];
        console.log(idToCheck);
        var decodedId = decodeURI(idToCheck)
        console.log(payload[this.key], decodedId)
        if (this.rulePathExceptions.length != 0 && payload[this.key] == decodedId) {
          var hasExceptions = this.rulePathExceptions.find(exception => options.path.includes(exception))
          return hasExceptions == undefined
        } else {
          return payload[this.key] == decodedId
        }

      } catch (e) {
        console.log(e);
        return false;
      }
    }
  };
}

var getApiAuthorization = async function (request, jwtclaims, policies) {
  console.log(request)
  console.log("GET API AUTHORIZATION")
  for (const policy of policies) {
    var policyOutcome = await evaluateRules(policy.rules, jwtclaims, request);
    console.log("####");
    console.log(policyOutcome);
    if (policyOutcome.authorized) {
      return policyOutcome;
    } else if (policyOutcome.message) {
      return policyOutcome;
    }
  }
  console.log("gets to past api policy iteration");
  if (api.authorizations.length > 0) {
    return { authorized: false };
  } else {
    return { authorized: true, jwt: jwtclaims };
  }
};


var getApiAuthorization = async function (
  api,
  action,
  method,
  jwtclaims,
  policies = []
) {
  //console.log(apiname);
  //console.log("#getApiAuthorization#Customer Identifer: " + customerIdentifier);
  if (policies.length == 0) {
    console.log("The Snapshot was Empty");
    return { authorized: true, jwt: jwtclaims };
  }

  var globalPolicies = [];
  const nonGlobalPolicies = policies.filter(policy => {
    if (policy.customRoute) {
      if (
        policy.customRoute.methods.includes(method.toString().toLowerCase()) &&
        policy.customRoute.path == action && policy.apiUrl == api
      ) {
        return policy;
      }
    } else if (policy.apiUrl == api) {
      globalPolicies.push(policy);
    }
  });

  if (nonGlobalPolicies.length > 0) {
    console.log("PAST NON GLOBAL");
    var apiSpecificAuthorizations = nonGlobalPolicies.sort(function (a, b) {
      return a.priority - b.priority;
    });
    //console.log("api specific", apiSpecificAuthorizations);
    //if global and !subsitute
    for (const policy of apiSpecificAuthorizations) {
      var policyOutcome = await evaluateRules(
        policy.rules,
        jwtclaims
      );
      if (policyOutcome.authorized) {
        return policyOutcome;
      } else if (policyOutcome.message) {
        return policyOutcome;
      }
    }
    // console.log("gets to past api policy iteration");
    // return { authorized: true, jwt: jwtclaims };
  }
  for (const policy of globalPolicies) {
    var policyOutcome = await evaluateRules(
      policy.rules,
      jwtclaims
    );
    console.log("this is the policy outcome", policyOutcome);
    if (policyOutcome.authorized) {
      return policyOutcome;
    } else if (policyOutcome.message) {
      return policyOutcome;
    }
  }
  console.log("gets to past api policy iteration");
  if (globalPolicies.length > 0) {
    return { authorized: false };
  } else {
    return { authorized: true, jwt: jwtclaims };
  }
};

var evaluateRules = async function (apiPolicyRules, claims) {
  var apiRulesOutcomes = [];
  if (apiPolicyRules.length > 0) {
    //response.json({ authorized: "spaghetti", jwt: jwt.claims });
    for (const rule of apiPolicyRules) {
      var evaulationRule = await new Rule(rule);
      await apiRulesOutcomes.push(evaulationRule.evaluate(claims));
      console.log("this is the first outcome", apiRulesOutcomes);
      console.log("##########");
    }
    console.log(apiRulesOutcomes);
    console.log("DO I GET HERE")
    if (apiRulesOutcomes.includes(true)) {
      return { authorized: true, jwt: claims };
    } else if (
      apiRulesOutcomes.includes("Allow Access") ||
      apiRulesOutcomes.includes("Deny Access") ||
      apiRulesOutcomes.includes("Require MFA") ||
      apiRulesOutcomes.includes("Require Identity Verification")
    ) {
      var outcome = apiRulesOutcomes.filter(item => typeof item == "string")[0];
      var results = {
        "Allow Access": { authorized: true },
        "Deny Access": { authorized: false },
        "Require MFA": {
          message: "you need to do MFA!"
        },
        "Require Identity Verification": {
          message: "you require id verification!"
        }
      };
      if (outcome == "Require MFA") {
        var mfa_result = await triggerOrVerifyMFA(claims);
        var mfa_responses = {
          "Sent MFA": results[outcome],
          Success: { authorized: true },
          Failure: { authorized: false },
          "Not Enrolled": { message: "Not enrolled in MFA" }
        };
        console.log("yaka yaka");
        console.log(mfa_responses[mfa_result]);
        console.log("yaka yaka");
        return mfa_responses[mfa_result];
      } else if (outcome == "Require Identity Verification") {
        var result = await checkIfBot(claims);
        if (result.success) {
          return { authorized: true };
        }
      }

      return results[outcome];
    } else {
      console.log("########## is bad");
      return { authorized: false };
    }
  }
};


var Ronin = function () { }

var validRoninToken = async function (token, ronin) {
  var company = ronin.company
  const roninJwtVerifier = new OktaJwtVerifier({
    issuer: "https://dev-1043781.okta.com/oauth2/default", assertClaims: {
      company: company
    }
  });
  if (ronin.company && ronin.company != "") {
    try {
      var token = await roninJwtVerifier.verifyAccessToken(token, "api://default")
      return true
    } catch (e) {
      console.log(e)
      return false
    }
  } else {
    throw ("ronin sdk is missing company")
  }

}

Ronin.prototype.checkToken = async function (token) {
  var ronin = this
  var tokenResult = await validRoninToken(token, ronin)
  return tokenResult
}

Ronin.prototype.checkIfExistsAndCreate = async function () {
  var dir = './ronin';
  var thing = ""
  try {
    var result = await fsPromises.access(dir)
    console.log(result)

  } catch (e) {
    console.log(e)
    var result = await fsPromises.mkdir(dir)
    console.log(result)
    return dir
  }

}

var getDb = async function () {
  var ronin = this
  const dbWrapper = require("sqlite");
  const sqlite3 = require("sqlite3").verbose();
  var dbFile = "./.data/ronin.db"
  var exists = fs.existsSync(dbFile)
  if (exists) {
    var db = await dbWrapper.open({
      filename: dbFile,
      driver: sqlite3.Database
    })
    try {
      console.log(dbFile)
      // The async / await syntax lets us write the db operations in a way that won't block the app
      // Database doesn't exist yet - create Choices and Log tables
      console.log("am I hhere")
      await db.run(
        "CREATE TABLE IF NOT EXISTS ApiPolicies (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, priority INTEGER,rules TEXT NOT NULL, path TEXT, methods TEXT)"
      );
      await db.run(
        "CREATE TABLE IF NOT EXISTS Policies (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, priority INTEGER,rules TEXT NOT NULL, path TEXT, authorization_server TEXT, vendor TEXT)"
      );


    } catch (dbError) {
      console.log("AM I HARE")
      console.error(dbError);
    }
    return db
  } else {
    await fsPromises.mkdir("./.data")
    await fsPromises.open(".data/ronin.db", 'w')
    var db = await getDb()
    return db
  }
}

var savePolicyToDb = async function (contents, db) {
  //var policyString = JSON.stringify(policy)
  for (var i = 0; i < contents.policies.length; i++) {
    var apiPolicy = contents.policies[i]
    var row = await db.get(`SELECT * FROM ApiPolicies WHERE name = '${apiPolicy.name}' ;`)
    console.log("this is the row", row)
    if (!row) {
      apiPolicy.customRoute = apiPolicy.customRoute || { methods: [""] }
      db.run(`INSERT INTO ApiPolicies (name, rules, methods, path, priority) VALUES ('${apiPolicy.name}', '${await JSON.stringify(apiPolicy.rules)}', '${apiPolicy.customRoute.methods.join(" ")}', '${apiPolicy.customRoute.path}', '${apiPolicy.priority}')`)
    } else {
      console.log(apiPolicy.methods)
      db.run("UPDATE ApiPolicies SET rules = $rules, methods = $methods, path = $path, priority = $priority WHERE name = $name", {
        $name: apiPolicy.name,
        $rules: await JSON.stringify(apiPolicy.rules),
        $methods: apiPolicy.methods,
        $path: apiPolicy.path,
        $priority: apiPolicy.priority
      });
    }
  }

  for (var i = 0; i < contents.globalPolicies.length; i++) {
    var globalPolicy = contents.globalPolicies[i]
    var row = await db.get(`SELECT * FROM Policies WHERE name = '${globalPolicy.name}' ;`)
    console.log("this is the row", row)
    if (!row) {
      console.log(globalPolicy)
      db.run(`INSERT INTO Policies (name, rules, authorization_server, vendor, priority) VALUES ('${globalPolicy.name}', '${await JSON.stringify(globalPolicy.rules)}', '${globalPolicy.authorizationServer}', '${globalPolicy.vendor}', '${globalPolicy.priority}')`)
    } else {
      console.log(apiPolicy.methods)
      db.run("UPDATE Policies SET rules = $rules, authorization_server = $authorization_server, vendor = $vendor, priority = $priority WHERE name = $name", {
        $name: globalPolicy.name,
        $rules: await JSON.stringify(globalPolicy.rules),
        $authorization_server: globalPolicy.authorizationServer,
        $vendor: globalPolicy.vendor,
        $priority: globalPolicy.priority
      });
    }
  }
}

var getDbPolicies = async function (db) {
  var policies = await db.all("SELECT * from Policies")
  var apiPolicies = await db.all("SELECT * from ApiPolicies")
  apiPolicies = apiPolicies.map(function (policy) {
    policy.rules = JSON.parse(policy.rules)
    return policy
  })
  policies = policies.map(function (policy) {
    policy.rules = JSON.parse(policy.rules)
    return policy
  })
  return { "policies": apiPolicies, "globalPolicies": policies }
}

var getSelfHostedPolicies = async function (contents) {
  console.log("contents in the read ronin policy", contents)
  var policies = contents.globalPolicies
  var apiPolicies = contents.policies
  apiPolicies = apiPolicies.map(function (policy) {
    if (typeof policy.rules === 'string') {
      policy.rules = JSON.parse(policy.rules)
    }
    return policy
  })
  policies = policies.map(function (policy) {
    if (typeof policy.rules === 'string') {
      policy.rules = JSON.parse(policy.rules)
    }
    return policy
  })
  return { "policies": apiPolicies, "globalPolicies": policies }
}

// Ronin.prototype.testDb = async function(contents) {
//   var db = await getDb()
//   await savePolicyToDb(contents, db)
//   var policies = await getDbPolicies(db)
//   return policies
// }

var prepareForOwnStore = async function (contents) {
  var globalPolicies = contents.globalPolicies
  var apiPolicies = contents.policies
  apiPolicies = apiPolicies.map(function (policy) {
    policy.rules = JSON.stringify(policy.rules)
    return policy
  })
  globalPolicies = globalPolicies.map(function (policy) {
    policy.rules = JSON.stringify(policy.rules)
    return policy
  })
  return { "policies": apiPolicies, "globalPolicies": globalPolicies }
}

Ronin.prototype.addRoninFile = async function (dir = "./ronin", contents, token, params = {}) {
  var ronin = this
  try {
    var filepath = dir || "./ronin"
    var goodToken = await validRoninToken(token, ronin)
    console.log("Is the token valid?", goodToken)
    console.log(dir + "/ronin.json")
    if (goodToken) {
      if (params.db) {
        await fsPromises.writeFile(filepath + "/ronin.json", JSON.stringify(contents))
        var db = await getDb()
        await savePolicyToDb(contents, db)
        return "saved to db"
      } else if (params.selfHosted) {
        var formattedPolicies = await prepareForOwnStore(contents)
        return formattedPolicies
      } else {
        await fsPromises.writeFile(filepath + "/ronin.json", JSON.stringify(contents))
      }
    } else {
      return "Token not provided"
    }
  } catch (e) {
    console.log(e)
    return
  }
}



Ronin.prototype.readRoninPolicy = async function (dir, params = {}) {
  try {
    if (params.db) {
      var db = await getDb()
      return await getDbPolicies(db)
    } else if (params.selfHostedPolicies) {
      console.log("options in the read ronin policy", params)
      var formattedPolicies = await getSelfHostedPolicies(params.selfHostedPolicies)
      return formattedPolicies
    } else {
      var filepath = dir || "./ronin"
      console.log(dir + "/ronin.json")
      var policy = await fsPromises.readFile(filepath + "/ronin.json")

      var parsedRule = await JSON.parse(policy, 'utf8')
      return parsedRule
    }
  } catch (e) {
    console.log(e)
    return
  }
}

var verifyOtherJwt = async function (policy, token) {
  const jose = require("jose");
  console.log("I AM HERE BEFORE JWkS")
  const JWKS = await jose.createRemoteJWKSet(
    new URL(policy.authorizationServer)
  );
  console.log("I AM HERE AFTER JWkS")
  const { payload, protectedHeader } = await jose.jwtVerify(token, JWKS, {
  });
  var jwt = { 'body': payload }
  console.log("jose payload", payload)
  return jwt;
};

var verifyOktaJwt = async function (policy, token) {
  console.log("i am hitting the new jwt verification method")
  const oktaJwtVerifier = new OktaJwtVerifier({
    issuer: policy.authorizationServer // required
  });

  var jwt = await oktaJwtVerifier.verifyAccessToken(token, [
    "api://special",
    "api://default",
    "api://super.unidemo"
  ]);
  return jwt;
};

var jwtVerication = async function (policy, token) {
  console.log("i am here")
  policy.authorizationServer = policy.authorizationServer || policy.authorization_server || ""
  console.log(policy)
  if (
    policy.vendor == "okta" ||
    policy.authorizationServer.includes("okta.com") ||
    policy.authorizationServer.includes("oktapreview.com")
  ) {
    try {
      var jwt = await verifyOktaJwt(policy, token);
      return jwt;
    } catch (e) {
      throw e;
    }
  } else {
    try {
      var jwt = await verifyOtherJwt(policy, token);
      return jwt
    } catch (e) {
      throw e;
    }
  }
};

var checkRonin = function (req, res, next, options) {
  return (req, res, next) => {
    console.log(req.ips)
    console.log(req.hostname)
    console.log(req.originalUrl.split("/")[1])
    console.log("this is the full url", req.originalUrl)
    console.log(req.method)
    console.log(req.headers)
    var axios = require("axios");
    var otp = req.headers.otp
    var device_token = req.headers.device_token
    var humantoken = req.headers.humantoken
    console.log(req.connection.remoteAddress)
    var bearerToken = "whatever"
    if (req.headers.authorization) {
      bearerToken = req.headers.authorization.split("Bearer ")[1]
      console.log(bearerToken)
    }
    var ip = requestIp.getClientIp(req);
    var config = {
      method: req.method,
      url: options.customerUrl,
      headers: {
        token: req.headers.token || bearerToken,
        api: "https://" + req.hostname,
        "x-forwarded-for": req.ips[req.ips.length - 3],
        action: req.originalUrl.split("/")[1],
        fullActionPath: req.originalUrl,
        method: req.method,
        ip: ip
      }
    };

    if (otp) {
      config.headers["otp"] = otp
    }
    if (humantoken) {
      config.headers["humantoken"] = humantoken
    }
    if (device_token) {
      config.headers["device_token"] = device_token
    }
    //next()
    //i
    axios(config)
      .then(function (response) {
        console.log(JSON.stringify(response.data));
        console.log(response.data.authorized);
        //res.send({"message": response.data})
        if (response.data.authorized) {
          next();
        } else if (response.data.message) {
          res.send({ "message": response.data.message })
        } else {
          res.send({ "message": "not authorized" })
        }
      })
      .catch(function (error) {
        console.log(error);
      });
    console.log("this is hit");
  };
};





Ronin.prototype.express = async function (req, res, next, options = {}) {
  if (options.cloud) {
    console.log("does it hit here?!?!?!?")
    var axios = require("axios");
    var otp = req.headers.otp
    var device_token = req.headers.device_token
    var humantoken = req.headers.humantoken
    console.log(req.connection.remoteAddress)
    var bearerToken = "whatever"
    if (req.headers.authorization) {
      bearerToken = req.headers.authorization.split("Bearer ")[1]
      console.log(bearerToken)
    }
    var ip = requestIp.getClientIp(req);
    var config = {
      method: req.method,
      url: options.customerUrl,
      headers: {
        token: req.headers.token || bearerToken,
        api: "https://" + req.hostname,
        "x-forwarded-for": ip,
        action: req.originalUrl.split("/")[1],
        fullActionPath: req.originalUrl,
        method: req.method,
        ip: ip
      }
    };

    if (otp) {
      config.headers["otp"] = otp
    }
    if (humantoken) {
      config.headers["humantoken"] = humantoken
    }
    if (device_token) {
      config.headers["device_token"] = device_token
    }
    //next()
    //i
    axios(config)
      .then(function (response) {
        console.log(JSON.stringify(response.data));
        console.log(response.data.authorized);
        //res.send({"message": response.data})
        if (response.data.authorized) {
          next();
        } else if (response.data.message) {
          res.send({ "message": response.data.message })
        } else {
          res.send({ "message": "not authorized" })
        }
      })
      .catch(function (error) {
        console.log(error);
      });
    console.log("this is hit");
  } else {
    var evaluation = await this.evaluate(req, options)
    if (evaluation.authorized) {
      next()
    } else {
      res.send({ message: "not authorized" })
    }
  }
}

Ronin.prototype.initialize = async function (options) {
  console.log(this)
  this.company = options.company
}





Ronin.prototype.awsAuthorize = async function(req, options) {
  var axios = require("axios");
  console.log(req)
  var otp = req.headers.otp;
  var device_token = req.headers.device_token;
  var humantoken = req.headers.humantoken;
  var bearerToken = "";
  if (req.headers.authorization) {
    bearerToken = req.headers.authorization.split("Bearer ")[1];
    console.log(bearerToken);
  }
  var ip = requestIp.getClientIp(req);
  var config = {
    method: "get",
    url: options.customerUrl,
    headers: {
      token: req.headers.token || bearerToken,
      api: "https://" + req.headers.host,
      "x-forwarded-for": ip,
      action: req.rawPath.split("/")[1],
      fullActionPath: req.rawPath,
      method: req.requestContext.http.method,
      ip: ip
    }
  };

  if (otp) {
    config.headers["otp"] = otp;
  }
  if (humantoken) {
    config.headers["humantoken"] = humantoken;
  }
  if (device_token) {
    config.headers["device_token"] = device_token;
  }
  console.log(config)
  console.log("this is the options", options)
  //next()
  //i
  try {
    var response = await axios(config)
    console.log(response)
    console.log(response.data.authorized);
     
        const result = {"isAuthorized": response.data.authorized || false, context: response.data}
        if (response.data.authorized) {
          console.log("this is the result for authorized", result)
          return result
        } else if (response.data.message) {
          console.log("this is the result for message", result)
          return result
        } else {
          console.log("this is the result for unauthorized", result)
          return result
        }
  } catch(e) {
    console.log(e)
    const result = {"isAuthorized": false, context: e}
    return result
  }
};


  // {
  //   "version": "2.0",
  //   "type": "REQUEST",
  //   "routeArn": "arn:aws:execute-api:us-east-1:123456789012:abcdef123/test/GET/request",
  //   "identitySource": ["user1", "123"],
  //   "routeKey": "$default",
  //   "rawPath": "/my/path",
  //   "rawQueryString": "parameter1=value1&parameter1=value2&parameter2=value",
  //   "cookies": ["cookie1", "cookie2"],
  //   "headers": {
  //     "Header1": "value1",
  //     "Header2": "value2"
  //   },
  //   "queryStringParameters": {
  //     "parameter1": "value1,value2",
  //     "parameter2": "value"
  //   },
  //   "requestContext": {
  //     "accountId": "123456789012",
  //     "apiId": "api-id",
  //     "authentication": {
  //       "clientCert": {
  //         "clientCertPem": "CERT_CONTENT",
  //         "subjectDN": "www.example.com",
  //         "issuerDN": "Example issuer",
  //         "serialNumber": "a1:a1:a1:a1:a1:a1:a1:a1:a1:a1:a1:a1:a1:a1:a1:a1",
  //         "validity": {
  //           "notBefore": "May 28 12:30:02 2019 GMT",
  //           "notAfter": "Aug  5 09:36:04 2021 GMT"
  //         }
  //       }
  //     },
  //     "domainName": "id.execute-api.us-east-1.amazonaws.com",
  //     "domainPrefix": "id",
  //     "http": {
  //       "method": "POST",
  //       "path": "/my/path",
  //       "protocol": "HTTP/1.1",
  //       "sourceIp": "IP",
  //       "userAgent": "agent"
  //     },
  //     "requestId": "id",
  //     "routeKey": "$default",
  //     "stage": "$default",
  //     "time": "12/Mar/2020:19:03:58 +0000",
  //     "timeEpoch": 1583348638390
  //   },
  //   "pathParameters": { "parameter1": "value1" },
  //   "stageVariables": { "stageVariable1": "value1", "stageVariable2": "value2" }
  // }



//check url path
//see if url path is matches applyType
// then check if the method is allowed 
// if global paths ignore original uri

Ronin.prototype.evaluate = async function (request, options = {}) {
  console.log("options in the evaluate", options)
  var item = await this.readRoninPolicy(undefined, options)
  console.log("makes it to the items", item)
  var globalPolicies = item.globalPolicies
  var apiPolicies = item.policies
  globalPolicies = globalPolicies.sort(function (a, b) {
    return a.priority - b.priority;
  })
  var accessTokenString = request.headers.token || "no token";
  if (accessTokenString.includes("Bearer ")) {
    accessTokenString = request.headers.token.split("Bearer ")[1];
  }

  var api = request.headers.api;
  var action = request.headers.action || "";
  var method = request.headers.method;
  var otp = request.headers.otp;
  var humanToken = request.headers.humantoken;

  console.log(request.headers);
  console.log(accessTokenString);
  //console.log(request.headers.otherawsdata[0]);
  //console.log(request.headers.event);
  // express helps us take JS objects and send them as JSON
  for (var i = 0; i < globalPolicies.length; i++) {
    var policy = globalPolicies[i]
    try {
      console.log(policy)
      var jwt = await jwtVerication(policy, accessTokenString);
      jwt.claims = jwt.claims || jwt.body
      console.log("claims claims", jwt.claims)
      jwt.claims.otp = otp;
      jwt.claims.humanToken = humanToken;
      var ruleOutcomes = [];
      if (policy.rules.length > 0) {
        //console.log("evaluating rules", apiPolicyRulesOutcome);
        //response.json({ authorized: true, jwt: jwt.claims });
        for (const rule of policy.rules) {
          var evaulationRule = await new Rule(rule);
          //console.log("in the for loop for final eval", evaulationRule);
          await ruleOutcomes.push(evaulationRule.evaluate(jwt.claims));
          if (ruleOutcomes.includes(true)) {
            console.log("IN THE TRUE for RULE OUTCOMES"); //
            //response.json({ authorized: true, jwt: jwt.claims });

            var apiPolicyRulesOutcome = await getApiAuthorization(
              api,
              action,
              method,
              jwt.claims,
            );
            console.log("end result");
            console.log(apiPolicyRulesOutcome);
            if (
              apiPolicyRulesOutcome.authorized == false ||
              apiPolicyRulesOutcome.message //you have to do mfa
            ) {
              return apiPolicyRulesOutcome
            } else {
              return apiPolicyRulesOutcome
            }
          }
        }
      }
    } catch (e) {
      console.log("in the jwt was not verified")
      console.log(e)
      //return { authorized: false };
    }
  }
  return { authorized: false }
}




module.exports = new Ronin();