rs.initiate(
   {
      _id: "main_shard1",
      version: 1,
      members: [
         { _id: 0, host : "main_shard1a:27018" },
      ]
   }
)
