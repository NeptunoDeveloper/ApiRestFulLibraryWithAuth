using System;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata;

namespace PrjWebApi01.Models
{
    public partial class LibraryContext : DbContext
    {
        public LibraryContext()
        {
        }

        public LibraryContext(DbContextOptions<LibraryContext> options)
            : base(options)
        {
            ChangeTracker.LazyLoadingEnabled = false;
        }

        public virtual DbSet<Authors> Authors { get; set; }
        public virtual DbSet<Books> Books { get; set; }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            if (!optionsBuilder.IsConfigured)
            {
#warning To protect potentially sensitive information in your connection string, you should move it out of source code. See http://go.microsoft.com/fwlink/?LinkId=723263 for guidance on storing connection strings.
                optionsBuilder
                .UseNpgsql("Host=localhost;Port=5432;User Id=postgres;Password=servidor;Database=Library");
            }
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.HasAnnotation("ProductVersion", "2.2.4-servicing-10062");

            modelBuilder.Entity<Authors>(entity =>
            {
                entity.HasKey(e => e.IdAuthor)
                    .HasName("pk_author");

                entity.ToTable("authors");

                entity.Property(e => e.IdAuthor)
                    .HasColumnName("id_author")
                    .HasColumnType("numeric(10,0)");

                entity.Property(e => e.Email)
                    .HasColumnName("email")
                    .HasMaxLength(30);

                entity.Property(e => e.LastName)
                    .HasColumnName("last_name")
                    .HasMaxLength(30);

                entity.Property(e => e.Name)
                    .HasColumnName("name")
                    .HasMaxLength(30);
            });

            modelBuilder.Entity<Books>(entity =>
            {
                entity.HasKey(e => e.IdBook)
                    .HasName("pk_book");

                entity.ToTable("books");

                entity.Property(e => e.IdBook)
                    .HasColumnName("id_book")
                    .HasColumnType("numeric(10,0)");

                entity.Property(e => e.Description)
                    .HasColumnName("description")
                    .HasMaxLength(200);

                entity.Property(e => e.Genre)
                    .HasColumnName("genre")
                    .HasMaxLength(30);

                entity.Property(e => e.IdAuthor)
                    .HasColumnName("id_author")
                    .HasColumnType("numeric(10,0)");

                entity.Property(e => e.Publisher)
                    .HasColumnName("publisher")
                    .HasMaxLength(30);

                entity.Property(e => e.Section)
                    .HasColumnName("section")
                    .HasMaxLength(20);

                entity.Property(e => e.Title)
                    .HasColumnName("title")
                    .HasMaxLength(30);

                entity.Property(e => e.Year).HasColumnName("year");

                entity.HasOne(d => d.IdAuthorNavigation)
                    .WithMany(p => p.Books)
                    .HasForeignKey(d => d.IdAuthor)
                    .HasConstraintName("fk_booksauthors");
            });
        }
    }
}
