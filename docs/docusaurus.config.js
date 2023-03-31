// @ts-check
// Note: type annotations allow type checking and IDEs autocompletion

const lightCodeTheme = require('prism-react-renderer/themes/github');
const darkCodeTheme = require('prism-react-renderer/themes/dracula');

const BASE_URL = '/';

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'vet',
  tagline: 'Identify Open Source Risks',
  url: 'https://docs.safedep.io',
  baseUrl: `${BASE_URL}`,
  onBrokenLinks: 'throw',
  onBrokenMarkdownLinks: 'warn',
  favicon: 'img/vet.png',

  organizationName: 'SafeDep',
  projectName: 'vet',
  trailingSlash: false,
  deploymentBranch: 'main',

  // Even if you don't use internalization, you can use this field to set useful
  // metadata like html lang. For example, if your site is Chinese, you may want
  // to replace "en" with "zh-Hans".
  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  presets: [
    [
      'classic',
      /** @type {import('@docusaurus/preset-classic').Options} */
      ({
        gtag: {
          trackingID: 'G-35RRJQMJ5Q',
          anonymizeIP: true,
        },
        docs: {
          routeBasePath: '/',
          sidebarPath: require.resolve('./sidebars.js'),
          // Please change this to your repo.
          // Remove this to remove the "edit this page" links.
          editUrl:
            'https://github.com/safedep/vet/tree/main/docs',
        },
        theme: {
          customCss: require.resolve('./src/css/custom.css'),
        },
      }),
    ],
  ],

  themeConfig:
    /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
    ({
      navbar: {
        title: 'Vet ⚡️ SafeDep',
        logo: {
          alt: 'SafeDep Vet',
          src: 'img/vet.png',
        },
        items: [
          // {
          //   type: 'doc',
          //   docId: 'quickstart',
          //   position: 'left',
          //   label: 'Quick Start',
          // },
          // {
          //   type: 'doc',
          //   docId: 'overview',
          //   position: 'left',
          //   label: 'Documentation',
          // },
          // {to: '/blog', label: 'Blog', position: 'left'},
          {
            href: 'https://github.com/safedep/vet',
            label: 'GitHub',
            position: 'right',
          },
          {
            href: 'https://twitter.com/safedepio',
            label: 'Twitter',
            position: 'right',
          },
          {
            href: 'https://rebrand.ly/safedep-community',
            label: 'Discord',
            position: 'right',
          },
          {
            href: 'https://www.producthunt.com/products/safedep-vet',
            label: 'Product Hunt',
            position: 'right',
          }
        ],
      },
      footer: {
        // links: [
        //   {
        //     title: 'Website',
        //     items: [
        //       {
        //         label: 'SafeDep',
        //         href: 'https://safedep.io',
        //       },
        //     ],
        //   },
        //   {
        //     title: 'Community',
        //     items: [
        //       {
        //         label: 'Discord',
        //         href: '#',
        //       },
        //     ],
        //   },
        //   {
        //     title: 'More',
        //     items: [
        //       {
        //         label: 'Blog',
        //         to: '/blog',
        //       },
        //       {
        //         label: 'GitHub',
        //         href: 'https://github.com/safedep/',
        //       },
        //     ],
        //   },
        // ],
        copyright: `Copyright © ${new Date().getFullYear()} - <a href="https://safedep.io" target = "_blank" rel = "noopener" >SafeDep</a>`,
      },
      prism: {
        theme: lightCodeTheme,
        darkTheme: darkCodeTheme,
      },
    }),
};

module.exports = config;
