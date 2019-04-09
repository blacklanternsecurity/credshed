rs.initiate(
   {
      _id: "meta_shard2",
      version: 1,
      members: [
         { _id: 0, host : "meta_shard2a:27018" },
      ]
   }
)
