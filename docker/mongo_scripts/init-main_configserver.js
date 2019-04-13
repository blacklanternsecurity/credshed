rs.initiate(
   {
      _id: "main_configserver",
      configsvr: true,
      version: 1,
      members: [
         { _id: 0, host : "main_config0:27017" }
      ]
   }
)