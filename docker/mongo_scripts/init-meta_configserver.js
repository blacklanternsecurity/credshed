rs.initiate(
   {
      _id: "meta_configserver",
      configsvr: true,
      version: 1,
      members: [
         { _id: 0, host : "meta_config0:27017" }
      ]
   }
)