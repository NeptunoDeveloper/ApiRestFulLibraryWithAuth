using System;
using System.Collections.Generic;

namespace PrjWebApi01.Models.DTO
{
    public class AuthorsDTO
    {
        public decimal IdAuthor { get; set; }
        public string Name { get; set; }
        public string LastName { get; set; }
        public string Email { get; set; }

        public virtual ICollection<BooksDTO> Books { get; set; }
    }
}
