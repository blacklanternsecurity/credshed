rs.initiate(
   {
      _id: "meta_shard1",
      version: 1,
      members: [
         { _id: 0, host : "meta_shard1a:27018" },
      ]
   }
)
