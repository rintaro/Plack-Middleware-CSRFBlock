use inc::Module::Install;
name 'Plack-Middleware-CSRFBlock';
all_from 'lib/Plack/Middleware/CSRFBlock.pm';
readme_from 'lib/Plack/Middleware/CSRFBlock.pm';
githubmeta;

# requires '';

tests 't/*.t';
author_tests 'xt';

build_requires 'Test::More';
auto_set_repository;
auto_include;
WriteAll;
