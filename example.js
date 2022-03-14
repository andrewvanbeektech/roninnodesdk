
(async function() {
  // var policy = require("")
  //   var token = process.argv[process.argv.length - 1].split("token=")[1] || "no token"
  //   var ronin = require("./index")
  //   var thing = await ronin.checkIfExistsAndCreate() 
  // //   console.log("this is the result", thing)
  // //  // await ronin.addRoninFile(thing, {"yo": "yeah"}, "lol")
  // //   var item = await ronin.readRoninPolicy(thing)
  //   //console.log(item)
  //   var request = {
  //     headers: {
  //       token: token
  //     }
  //   }
  //   var item = await ronin.evaluate(request)
  //   console.log("this is the item", item)
  var ronin = require("./index")
  ronin.intialize({company: "yeah"})
  ronin.otherMethod()
  //var policies = await ronin.testDb(policy)
  //console.log("policies from the database", policies)
  //await ronin.savePolicyToDb(policy, database)
  //var policies = await ronin.getDbPolicies(database)
  //console.log(policies)
  })();