// SP10 graph fixture (node): a Mongo operator key is a nosql sink.
function find(db, name) {
  return db.collection('u').find({ name: { $ne: null } });
}

module.exports = { find };
