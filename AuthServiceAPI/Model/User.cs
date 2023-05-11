﻿using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using System.Collections.Generic;

namespace AuthServiceAPI.Model
{
    public class User
    {
        [BsonId]
        [BsonElement(elementName: "_id")]
        public ObjectId UserID { get; set; }
        public string? Username { get; set; }
        public string? Password { get; set; }
        public string? Name { get; set; }
        public string? Address { get; set; }
        public string? Phone { get; set; }
        public string? Email { get; set; }
        public bool Verified { get; set; }
        public float Rating { get; set; }

        public User()
        {
        }
    }
}

