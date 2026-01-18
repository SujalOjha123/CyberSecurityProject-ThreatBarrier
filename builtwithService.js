const BuiltWith = require("builtwith-api");

const builtwith = BuiltWith(process.env.BUILTWITH_API_KEY, {
  responseFormat: "json",
});

async function domainLookup(url) {
  return await builtwith.domain(url, {
    onlyLiveTechnologies: true,
    noMetaData: true,
    noAttributeData: true,
  });
}

module.exports = { domainLookup };
