var express = require('express');
var router = express.Router();

/* GET home page. */
router.get('/', function(req, res, next) {
  let coords=[];
  req.app.locals.dataStore.forEach(report => {
    //coords.push( `new google.maps.LatLng(${report.lat},${report.lon})`);
    let threatlevel = 1;
    if(report.threatlevel === 'high') threatlevel = 3;
    if(report.threatlevel === 'medium') threatlevel = 2;
    
    coords.push( `[${threatlevel},${report.lat},${report.lon}, 1]`);
  })
  let coordstr =  '['+coords.join(',')+']';

  let alerts = analyseReports(req.app.locals.dataStore);

  res.render('index', { title: 'Lowbar: lowering the threat reporting bar', coords:coordstr, reports: req.app.locals.dataStore, alerts: alerts });
});

router.post('/reportthreat', reportThreat)


function reportThreat(req, res, next){
  req.app.locals.dataStore.unshift(req.body); //add to front of array so most recent first

  res.status(200).send('Threat report logged');
}

function analyseReports(dataStore){
  return [{threatlevel: 'high', "lat": "53.477131", "lon": "-2.254062", type: 'Suspected bomb attack' }, {threatlevel: 'medium', "lat": "53.477", "lon": "-2.253", type: 'Suspected vehicle attack' }];

  // // We want to look for clusters of reports in a location
  
  // getDistanceFromLatLonInKm

}


function getDistanceFromLatLonInKm(lat1,lon1,lat2,lon2) {
  var R = 6371; // Radius of the earth in km
  var dLat = deg2rad(lat2-lat1);  // deg2rad below
  var dLon = deg2rad(lon2-lon1); 
  var a = 
    Math.sin(dLat/2) * Math.sin(dLat/2) +
    Math.cos(deg2rad(lat1)) * Math.cos(deg2rad(lat2)) * 
    Math.sin(dLon/2) * Math.sin(dLon/2)
    ; 
  var c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a)); 
  var d = R * c; // Distance in km
  return d;
}

function deg2rad(deg) {
  return deg * (Math.PI/180)
}

module.exports = router;
