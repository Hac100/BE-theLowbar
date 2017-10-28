var express = require('express');
var router = express.Router();

/* GET home page. */
router.get('/', function (req, res, next) {
  let coords = [];
  req.app.locals.dataStore.forEach(report => {
    //coords.push( `new google.maps.LatLng(${report.lat},${report.lon})`);
    let threatlevel = 1;
    if (report.threatlevel === 'high') threatlevel = 3;
    if (report.threatlevel === 'medium') threatlevel = 2;

    coords.push(`[${threatlevel},${report.lat},${report.lon}, 1]`);
  })
  let coordstr = '[' + coords.join(',') + ']';

  let alerts = analyseReports(req.app.locals.dataStore);

  res.render('index', { title: 'Lowbar: lowering the threat reporting bar', coords: coordstr, reports: req.app.locals.dataStore, alerts: alerts });
});

router.post('/reportthreat', reportThreat)


function reportThreat(req, res, next) {
  req.app.locals.dataStore.unshift(req.body); //add to front of array so most recent first

  res.status(200).send('Threat report logged');
}

function analyseReports(dataStore) {
  // let alerts = [];
  // alerts.push({threatlevel: 1, "lat": "53.477131", "lon": "-2.254062", type: 'Suspected bomb attack' });
  // alerts.push({threatlevel: 2, "lat": "53.477000", "lon": "-2.253000", type: 'Suspected vehicle attack' });
  // return alerts;
  // // // We want to look for clusters of reports in a location
  let alerts = [];
  // Should really try automated clustering but for now let's take the reports in order and detect if they are close, start a new cluster if too big gap
  let ds = dataStore;

  let ds = dataStore;
  let clusters = [];
  let clusterStart = ds[0];
  let currentCluster = [];
  currentCluster.push(clusterStart);
  let distThresh = 0.25;
  for(let i = 1; i<ds.length; i++ )
  {
    if(getDistanceFromLatLonInKm(ds[i]['lat'], ds[i]['lon'], ds[i-1]['lat'], ds[i-1]['lon'])<distThresh)
    {
      currentCluster.push(ds[i]);
    }else{
      clusters.push(currentCluster);
      currentCluster = [];
      currentCluster.push(ds[i]);
    }
  }
  clusters.push(currentCluster);

  console.log(clusters);
  // apply some simple rules to clusters


  return alerts;
}


function getDistanceFromLatLonInKm(lat1, lon1, lat2, lon2) {
  var R = 6371; // Radius of the earth in km
  var dLat = deg2rad(lat2 - lat1);  // deg2rad below
  var dLon = deg2rad(lon2 - lon1);
  var a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(deg2rad(lat1)) * Math.cos(deg2rad(lat2)) *
    Math.sin(dLon / 2) * Math.sin(dLon / 2)
    ;
  var c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  var d = R * c; // Distance in km
  return d;
}

function deg2rad(deg) {
  return deg * (Math.PI / 180)
}

module.exports = router;
