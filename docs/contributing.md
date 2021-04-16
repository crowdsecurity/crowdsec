# Contributing

You have an idea, a suggestion or you spotted a mistake ?
Help us improve the software and the user experience, to make the internet a safer place together !



## Contributing to the documentation

If you spotted some mistakes in the documentation or have improvement suggestions, you can :

 - open a {{v1X.doc.new_issue}} if you are comfortable with github
 - let us know on {{v1X.doc.discourse}} if you want to discuss about it

Let us as well know if you have some improvement suggestions !


<details>
  <summary>Preview your documentation changes locally</summary>

```bash
python3 -m venv cs-env
source cs-env/bin/activate
pip install -r docs/requirements.txt
mkdocs serve
```

</details>


## Contributing to the code

 - If you want to report a bug, you can use [the github bugtracker]({{v1X.crowdsec.bugreport}})
 - If you want to suggest an improvement you can use either [the github bugtracker]({{v1X.crowdsec.bugreport}}) or the {{v1X.doc.discourse}} if you want to discuss 


## Contributing to the parsers/scenarios

If you want to contribute your parser or scenario to the community and have them appear on the {{v1X.hub.htmlname}}, you should [open a merge request](https://github.com/crowdsecurity/hub/pulls) on the hub.

We are currently working on a proper [CI](https://en.wikipedia.org/wiki/Continuous_integration) for the {{v1X.hub.htmlname}}, so for now all contribution are subject to peer-review, please bear with us !

## Contacting the team

If you want to contact us using non-public media, you can contact us on `support` AT `crowdsec` DOT `net` with the following gpg-key :

```
-----BEGIN PGP PUBLIC KEY BLOCK-----
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
=Edl+
-----END PGP PUBLIC KEY BLOCK-----
```


## Publishing bouncers

We do welcome bouncers from the community, and will gladly publish them on the hub.

### Why ?

Sharing your bouncer on the hub allows other users to find it and use it. While increasing your code's visibility, it ensures as well a benevolent look from the community and the team over it.

### How ?

To have your bouncer published on the hub, please simply [open a new issue on the hub](https://github.com/crowdsecurity/hub/issues/new), requesting "bouncer inclusion". The bouncer will then be reviewed by the team, and then will be published directly on the hub, for everyone to find & use it !


The information that should be stated in your issue are :

 - The source repository of your bouncer (for example `https://github.com/crowdsecurity/cs-firewall-bouncer/`)
 - The software licence used
 - The current status of the bouncer (stage : dev/unstable/stable)
 - Documentation (can be simply in the README.md) :
    - must contains : installing, uninstalling
    - should contains : configuration documentation 
 - Link to existing tests if applicable (functional tests or unit tests)

Please take care of the following :

 - Ensure your repository has a About/Short description meaningful enough : it will be displayed in the hub
 - Ensure your repository has a decent README.md file : it will be displayed in the hub
 - Ensure your repository has *at least* one release : this is what users will be looking for
 - (ideally) Have a "social preview image" on your repository : this will be displayed in the hub when available
 - (ideally) A Howto or link to guide that provides a hands-on experience with the bouncer


Please find below a template :

```markdown
Hello,

I would like to suggest the addition of the `XXXX` to the hub :

 - Source repository: https://github.com/xxx/xxx/
 - Licence : MIT
 - Current status : stable (has been used in production for a while)
 - README/doc : https://github.com/xxx/xxx/blob/main/README.md
 - Existing tests :
    - functional tests : https://github.com/xxx/xxx/blob/main/.github/workflows/tests.yml

 - Short/Long description : OK
 - Howto : in README
 - At least one release : yes

```

## Publishing parsers, scenarios and collections

### Why ?

Sharing your parsers, scenarios and collections on the hub allows other users to find it and use it. While increasing your code's visibility, it ensures as well a benevolent look from the community and the team over it.

### How ?

To have your parser/scenario published on the hub, please simply [open a new issue on the hub](https://github.com/crowdsecurity/hub/issues/new), requesting "parser/scenario inclusion". The configurations will then be reviewed by the team, and then will be published directly on the hub, for everyone to find & use it !

