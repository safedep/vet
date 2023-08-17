import logging
import os

logging.basicConfig(level=logging.DEBUG)

rootdir = os.path.abspath(os.path.dirname(__file__))
name = open(os.path.join(rootdir, 'NAME')).read().strip()
version = open(os.path.join(rootdir, 'VERSION')).read().strip()
#long_description = open(os.path.join(rootdir, 'README.md')).read()
long_description = "Awesome XXXXX Framework"

install_requires1 = [
            "filetype>=1.0.5",
            "pyunpack>=0.1.2",
            "patool>=1.12",
            "wordninja>=2.0.0",
            "iocextract>=1.13.1",
            # "pyparsing==2.4.2", # Changing to fixed Version : Pyparsing library deprecated. (ERROR: cannot import name 'downcaseTokens' from 'pyparsing')
            "pyparsing>=3.0.8", 
            "ioc-fanger",
            "titlecase>=0.12.0",
            "furl>=2.1.0",
            "pathlib2>=2.3.3",
            "lxml>=4.5.0",
    ],

install_requires2 = [
                "food-exceptions>=0.4.4",
            "food-models>=3.3.1",
            "dateutils>=0.6.6",
            "publicsuffixlist>=0.6.2",
            "dnspython",
            "netaddr>=0.7.18",
            "validators>=0.12.2",
            "fqdn>=1.1.0",
            "tld>=0.9.1",
            "cchardet>=2.1.4",
            "urllib3>=1.22",
            "tldextract>=2.2.0",
]

def get1():
    return install_requires1 + install_requires2 +  ["fuzzywuzzy>=0.18.0", "PySocks>=1.7.0", "truffleHogRegexes>=0.0.7", "soupsieve>=1.9.1"]


setup(
    name=name,
    packages=find_packages(),
    version=version,
    description="Sensor framework and Modules",
    long_description=long_description,
    author='Jitendra Chauhan',
    author_email='jitendra.chauhan@xxxxx.com',
    url="",
    include_package_data=True,
    #    python_requires='>=2.7,>=3.5,<4.0',
    install_requires=get1() + ["iptools>=0.7.0", "parsedatetime>=2.4", "beautifulsoup4>=4.7.1"],
    setup_requires=[],
    tests_require=["nose"],
    # cmdclass={'test': PyTest},
)
