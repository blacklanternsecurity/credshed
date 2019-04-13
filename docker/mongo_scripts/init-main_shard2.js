rs.initiate(
   {
      _id: "main_shard2",
      version: 1,
      members: [
         { _id: 0, host : "main_shard2a:27018" },
      ]
   }
)
