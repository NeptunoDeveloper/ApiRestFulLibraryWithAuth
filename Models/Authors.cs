using System;
using System.Collections.Generic;

namespace PrjWebApi01.Models
{
    public partial class Authors
    {
        public Authors()
        {
            Books = new HashSet<Books>();
        }

        public decimal IdAuthor { get; set; }
        public string Name { get; set; }
        public string LastName { get; set; }
        public string Email { get; set; }

        public virtual ICollection<Books> Books { get; set; }
    }
}
