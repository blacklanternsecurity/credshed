rs.initiate(
   {
      _id: "shard0",
      version: 1,
      members: [
         { _id: 0, host : "shard0a:27018" },
      ]
   }
)
