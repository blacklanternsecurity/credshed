rs.initiate(
   {
      _id: "main_shard3",
      version: 1,
      members: [
         { _id: 0, host : "main_shard3a:27018" },
      ]
   }
)
