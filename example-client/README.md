# [Stitchz Social Login](http://www.stitchz.net)

Stitchz Social Login & Network Sharing is a centralized service for authenticating end users against their
social network identity. The extended API allows your users to make additional calls against authorized
and approved social network resources, i.e. Facebook, Twitter, tumblr, etc.

This example solution was built to demonstrate how to leverage the Stitchz.net API, including making secure
OAuth requests and token exchange. The token can be used to make future secure requests for additional 
social network information.


## Getting Started
To get started simply download this entire package, open in Visual Studio, then update Startup.Auth.cs with 
your Stitchz.net application's ApiKey and AppSecret. Copy each value to to the ClientId and ClientSecret 
respectively. If you've logged into Stitchz.net with Facebook, Twitter, tumblr, Pinterest, Reddit, Flickr, 
LinkedIn, SoundCloud, or Discogs, then change the "identity" variable to match your social identity's 
"identifier". Your identifier will look something like this: http://twitter.com/stitchzdotnet#195980728

If you don't have a Stitchz account, go to <https://login.stitchz.net/> and create a free application. 

## Requirements
This example package was built with Visual Studio 2015 and includes several nuget packages, including 
Newtonsoft.Json and OWIN. 


## Documentation
Complete documentation on the Stitchz.net API can be found at <http://www.stitchz.net/Documentation>.


## Contributing


Copyright (c) 2016 Stitchz.net
