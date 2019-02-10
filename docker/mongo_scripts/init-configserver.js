rs.initiate(
   {
      _id: "configserver",
      configsvr: true,
      version: 1,
      members: [
         { _id: 0, host : "config0:27017" },
         { _id: 1, host : "config1:27017" }
      ]
   }
)