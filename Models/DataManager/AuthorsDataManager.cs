using System.Collections;
using System.Linq;
using System.Collections.Generic;
using PrjWebApi01.Models;
using PrjWebApi01.Models.DTO;
using PrjWebApi01.Models.Repository;
using Microsoft.EntityFrameworkCore;

namespace PrjWebApi01.Models.DataManager
{
    public class AuthorsDataManager: IDataRepository<Authors, AuthorsDTO>
    {
        readonly LibraryContext _libraryContext;
        public AuthorsDataManager(LibraryContext pLibraryContext)
        {
            _libraryContext = pLibraryContext;
        }

        public IEnumerable<Authors> GetAll()
        {
            return _libraryContext.Authors.Include(c=> c.Books).ToList();
        }

        public Authors Get(long id)
        {
            return _libraryContext.Authors.Include(c => c.Books).SingleOrDefault(c => c.IdAuthor == id);
        }

        public void Add(Authors entity)
        {
            _libraryContext.Authors.Add(entity);
            _libraryContext.SaveChanges();
        }

        public void Update(Authors entityToUpdate, Authors entity)
        {
            entityToUpdate = _libraryContext.Authors
                .Include(a => a.Books)
                .Single(b => b.IdAuthor == entityToUpdate.IdAuthor);

            entityToUpdate.Name = entity.Name;
            var deletedBooks = entityToUpdate.Books.Except(entity.Books).ToList();
            var addedBooks = entity.Books.Except(entityToUpdate.Books).ToList();

            deletedBooks.ForEach(bookToDelete =>
                entityToUpdate.Books.Remove(
                    entityToUpdate.Books
                        .First(b => b.IdBook == bookToDelete.IdBook)));

            foreach (var addedBook in addedBooks)
            {
                _libraryContext.Entry(addedBook).State = EntityState.Added;
            }

            _libraryContext.SaveChanges();
        }

        public void Delete(Authors entity)
        {
            throw new System.NotImplementedException();
        }
    }
}