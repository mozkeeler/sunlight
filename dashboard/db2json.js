var sqliteToJSON = require('sqlite-to-json');
var sqlite3 = require('sqlite3');

var exporter = new sqliteToJSON({
  client: new sqlite3.Database('BRs.db')
});

exporter.save('issuerReputation', 'issuerReputation.json', function(err) {
  if (err) {
    console.log('error exporting: ' + err);
  }
});
