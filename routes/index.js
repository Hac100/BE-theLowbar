var express = require('express');
var router = express.Router();

/* GET home page. */
router.get('/', function(req, res, next) {
  let coords=[];
  req.app.locals.dataStore.forEach(report => {
    coords.push( `new google.maps.LatLng(${report.lat},${report.lon})`);
  })
  let coordstr =  '['+coords.join(',')+']';
  console.log(coordstr)
  //res.render('index', { title: 'Lowbar: lowering the threat reporting bar', coords: '[    new google.maps.LatLng(53.477131, -2.254062),            new google.maps.LatLng(53.477, -2.254062),            new google.maps.LatLng(53.477, -2.2530),            new google.maps.LatLng(53.477131, -2.253)   ];' });
  res.render('index', { title: 'Lowbar: lowering the threat reporting bar', coords:coordstr });
});

router.post('/reportthreat', reportThreat)


function reportThreat(req, res, next){
  req.app.locals.dataStore.unshift(req.body); //add to front of array so most recent first

  res.status(200).send('Threat report logged');
}


module.exports = router;
