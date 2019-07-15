using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;

namespace PrjWebApi01.Models.DTO
{
    public class BooksDTO
    {
        public decimal IdBook { get; set; }
        public decimal? IdAuthor { get; set; }
        public string Title { get; set; }
        public string Description { get; set; }
        public string Section { get; set; }
        public string Genre { get; set; }
        public int? Year { get; set; }
        public string Publisher { get; set; }

        public virtual AuthorsDTO Author { get; set; }
    }
}
