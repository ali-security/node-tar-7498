// Tests for path/linkpath sanitization CVEs.
// Adapted from upstream test/ghsa-8qq5-rm4j-mr97.ts for 2.2.1's API (tap 0.x + tar.Extract).
// Each CVE's patch adds its own tests to this file.

var tap = require("tap")
var tar = require("../tar.js")
var TarHeader = require("../lib/header.js")
var fs = require("fs")
var path = require("path")
var rimraf = require("rimraf")
var mkdirp = require("mkdirp")

var target = path.resolve(__dirname, "tmp/ghsa-8qq5")
var tarFile = path.resolve(__dirname, "tmp/ghsa-8qq5.tar")

function makeHeader(props) {
  return TarHeader.encode({
    path: props.path, mode: props.mode || 0644, uid: 0, gid: 0,
    size: props.size || 0, mtime: 0, cksum: 0, type: props.type,
    linkpath: props.linkpath || '', ustar: 'ustar\0', ustarver: '00',
    uname: '', gname: '', devmaj: 0, devmin: 0, fill: ''
  })
}

function buildTar(entries) {
  var chunks = []
  for (var i = 0; i < entries.length; i++) chunks.push(makeHeader(entries[i]))
  chunks.push(new Buffer(1024))
  for (var j = 0; j < 1024; j++) chunks[chunks.length - 1][j] = 0
  return Buffer.concat(chunks)
}

tap.test("preclean", function (t) {
  rimraf.sync(target)
  rimraf.sync(tarFile)
  mkdirp.sync(path.dirname(tarFile))
  t.pass("cleaned")
  t.end()
})

// CVE-2026-29786: drive-relative path c:../escape.txt is rejected
// The fix reorders: strip absolute root THEN check '..'.
// Before: c:../foo split to ['c:..', 'foo'] — no '..' match, not caught on Linux.
// After: strip 'c:' root → '../foo' → split → '..' detected → rejected.
tap.test("CVE-2026-29786: drive-relative path c:../escape.txt is rejected", function (t) {
  rimraf.sync(target)
  mkdirp.sync(target)
  var escapeFile = path.resolve(target, "..", "cve29786-escape-" + process.pid + ".txt")

  var tarBuf = buildTar([
    { path: "c:../cve29786-escape-" + process.pid + ".txt", type: "0", size: 0 }
  ])
  fs.writeFileSync(tarFile, tarBuf)

  var extractor = tar.Extract({ path: target })
    .on("end", function () {
      var exists = false
      try { fs.lstatSync(escapeFile); exists = true } catch (e) {}
      t.equal(exists, false,
        "c:../escape file should not be created outside target")
      t.end()
    })

  fs.createReadStream(tarFile).pipe(extractor)
})

// CVE-2026-29786: absolute path with '..' is stripped before '..' check
// /../a/target: strip '/' → '../a/target' → '..' detected → rejected (for path).
tap.test("CVE-2026-29786: absolute path with embedded '..' is rejected after stripping", function (t) {
  rimraf.sync(target)
  mkdirp.sync(target)

  var tarBuf = buildTar([
    { path: "/../a/target.txt", type: "0", size: 0 }
  ])
  fs.writeFileSync(tarFile, tarBuf)

  var extractor = tar.Extract({ path: target })
    .on("end", function () {
      // '../a/target.txt' should be rejected because '..' in path
      var exists = false
      try { fs.lstatSync(path.resolve(target, "../a/target.txt")); exists = true } catch (e) {}
      t.equal(exists, false,
        "/../a/target.txt should be rejected after stripping root")
      t.end()
    })

  fs.createReadStream(tarFile).pipe(extractor)
})

// CVE-2026-23745: hardlink with '..' linkpath does not link to external file
tap.test("CVE-2026-23745: hardlink with '..' linkpath does not link to external file", function (t) {
  rimraf.sync(target)
  mkdirp.sync(target)
  var secretFile = path.resolve(target, "..", "ghsa-secret-" + process.pid + ".txt")
  fs.writeFileSync(secretFile, "ORIGINAL DATA")
  var secretInode = fs.lstatSync(secretFile).ino

  var tarBuf = buildTar([
    { path: "sub/", type: "5", mode: 0755 },
    { path: "sub/exploit_sub", type: "1", linkpath: "../ghsa-secret-" + process.pid + ".txt" }
  ])
  fs.writeFileSync(tarFile, tarBuf)

  var done = false
  function finish() {
    if (done) return
    done = true
    var exploitPath = path.resolve(target, "sub/exploit_sub")
    try {
      var exploitStat = fs.lstatSync(exploitPath)
      t.notEqual(exploitStat.ino, secretInode,
        "exploit_sub must not share inode with external secret (hardlink blocked)")
    } catch (e) {
      t.pass("exploit_sub was not created at all (hardlink blocked)")
    }
    t.equal(fs.readFileSync(secretFile, 'utf8'), "ORIGINAL DATA",
      "external secret file must remain unchanged")
    try { fs.unlinkSync(secretFile) } catch (e) {}
    t.end()
  }

  var extractor = tar.Extract({ path: target })
    .on("end", finish)
    .on("error", finish)
  var rs = fs.createReadStream(tarFile)
  rs.on("error", finish)
  rs.pipe(extractor).on("error", finish)
})

// CVE-2026-23745: absolute linkpath has root stripped
tap.test("CVE-2026-23745: absolute linkpath has root stripped", function (t) {
  rimraf.sync(target)
  var tarBuf = buildTar([
    { path: "a/", type: "5", mode: 0755 },
    { path: "a/abs_sym", type: "2", linkpath: "/some/absolute/path" }
  ])
  fs.writeFileSync(tarFile, tarBuf)

  var extractor = tar.Extract({ path: target })
    .on("end", function () {
      try {
        var linkTarget = fs.readlinkSync(path.resolve(target, "a/abs_sym"))
        t.notEqual(linkTarget, "/some/absolute/path",
          "absolute symlink target should have been stripped")
        t.equal(linkTarget.charAt(0) !== "/", true,
          "stripped symlink target should be relative: got " + linkTarget)
      } catch (err) {
        t.fail("symlink should have been created with stripped linkpath: " + err.message)
      }
      t.end()
    })

  fs.createReadStream(tarFile).pipe(extractor)
})

// CVE-2026-23745: writeFileSync through extracted hardlink does not modify external secret
tap.test("CVE-2026-23745: writeFileSync through extracted hardlink does not modify external secret", function (t) {
  rimraf.sync(target)
  mkdirp.sync(target)
  var secretFile = path.resolve(target, "..", "ghsa-writefile-" + process.pid + ".txt")
  fs.writeFileSync(secretFile, "ORIGINAL DATA")

  var tarBuf = buildTar([
    { path: "exploit_hard", type: "1", linkpath: secretFile }
  ])
  fs.writeFileSync(tarFile, tarBuf)

  var done = false
  function finish() {
    if (done) return
    done = true
    var exploitPath = path.resolve(target, "exploit_hard")
    try { fs.writeFileSync(exploitPath, "OVERWRITTEN") } catch (e) {}
    t.equal(fs.readFileSync(secretFile, 'utf8'), "ORIGINAL DATA",
      "external secret must NOT be modified via extracted hardlink (writeFileSync exploit)")
    try { fs.unlinkSync(secretFile) } catch (e) {}
    t.end()
  }

  var extractor = tar.Extract({ path: target })
    .on("end", finish)
    .on("error", finish)
  var rs = fs.createReadStream(tarFile)
  rs.on("error", finish)
  rs.pipe(extractor).on("error", finish)
})

// CVE-2026-23745 + sub-directory variant: writeFileSync through sub/exploit_sub
tap.test("CVE-2026-23745: writeFileSync through sub/exploit_sub does not modify external secret", function (t) {
  rimraf.sync(target)
  mkdirp.sync(target)
  var secretName = "ghsa-subwrite-" + process.pid + ".txt"
  var secretFile = path.resolve(target, "..", secretName)
  fs.writeFileSync(secretFile, "SECRET DATA")

  var tarBuf = buildTar([
    { path: "sub/", type: "5", mode: 0755 },
    { path: "sub/exploit_sub", type: "1", linkpath: "../" + secretName }
  ])
  fs.writeFileSync(tarFile, tarBuf)

  var done = false
  function finish() {
    if (done) return
    done = true
    var exploitPath = path.resolve(target, "sub/exploit_sub")
    try { fs.writeFileSync(exploitPath, "OVERWRITTEN") } catch (e) {}
    t.equal(fs.readFileSync(secretFile, 'utf8'), "SECRET DATA",
      "external secret must NOT be modified via sub/exploit_sub writeFileSync")
    try { fs.unlinkSync(secretFile) } catch (e) {}
    t.end()
  }

  var extractor = tar.Extract({ path: target })
    .on("end", finish)
    .on("error", finish)
  var rs = fs.createReadStream(tarFile)
  rs.on("error", finish)
  rs.pipe(extractor).on("error", finish)
})

// CVE-2026-29786: escape-attempting drive-relative symlink linkpath (4+ levels of '..')
// After stripping 'c:', linkpath contains enough '..' to escape — rejected or neutered.
tap.test("CVE-2026-29786: escape-attempting drive-relative symlink linkpath is handled", function (t) {
  rimraf.sync(target)
  var tarBuf = buildTar([
    { path: "a/", type: "5", mode: 0755 },
    { path: "a/winrootdotsescapelink", type: "2", linkpath: "c:..\\..\\..\\..\\foo\\bar" }
  ])
  fs.writeFileSync(tarFile, tarBuf)

  var extractor = tar.Extract({ path: target })
    .on("end", function () {
      var linkPath = path.resolve(target, "a/winrootdotsescapelink")
      try {
        var linkTarget = fs.readlinkSync(linkPath)
        t.equal(linkTarget.indexOf("c:"), -1,
          "drive prefix stripped even for escape-attempting linkpath: got " + linkTarget)
      } catch (err) {
        t.pass("escape-attempting symlink not created: " + err.code)
      }
      t.end()
    })

  fs.createReadStream(tarFile).pipe(extractor)
})

// CVE-2026-24842: symlink with '..' linkpath is ALLOWED (only hardlinks reject '..')
tap.test("CVE-2026-24842: symlink with '..' linkpath is allowed", function (t) {
  rimraf.sync(target)
  var tarBuf = buildTar([
    { path: "sub/", type: "5", mode: 0755 },
    { path: "sub/rel_sym", type: "2", linkpath: "../some/target" }
  ])
  fs.writeFileSync(tarFile, tarBuf)

  var extractor = tar.Extract({ path: target })
    .on("end", function () {
      try {
        var linkTarget = fs.readlinkSync(path.resolve(target, "sub/rel_sym"))
        t.equal(linkTarget, "../some/target",
          "symlink with relative '..' linkpath should be preserved")
      } catch (err) {
        t.fail("symlink with '..' should be created: " + err.message)
      }
      t.end()
    })

  fs.createReadStream(tarFile).pipe(extractor)
})

// CVE-2026-24842: hardlink with '..' linkpath is still rejected
tap.test("CVE-2026-24842: hardlink with '..' does not link to external file", function (t) {
  rimraf.sync(target)
  mkdirp.sync(target)
  var secretFile = path.resolve(target, "..", "ghsa-secret2-" + process.pid + ".txt")
  fs.writeFileSync(secretFile, "SECRET")
  var secretInode = fs.lstatSync(secretFile).ino

  var tarBuf = buildTar([
    { path: "sub/", type: "5", mode: 0755 },
    { path: "sub/hardlink", type: "1", linkpath: "../ghsa-secret2-" + process.pid + ".txt" }
  ])
  fs.writeFileSync(tarFile, tarBuf)

  var done = false
  function finish() {
    if (done) return
    done = true
    var hardlinkPath = path.resolve(target, "sub/hardlink")
    try {
      var hardlinkStat = fs.lstatSync(hardlinkPath)
      t.notEqual(hardlinkStat.ino, secretInode,
        "hardlink must not share inode with external secret")
    } catch (e) {
      t.pass("hardlink was not created")
    }
    t.equal(fs.readFileSync(secretFile, 'utf8'), "SECRET",
      "external secret file must remain unchanged")
    try { fs.unlinkSync(secretFile) } catch (e) {}
    t.end()
  }

  var extractor = tar.Extract({ path: target })
    .on("end", finish)
    .on("error", finish)
  var rs = fs.createReadStream(tarFile)
  rs.on("error", finish)
  rs.pipe(extractor).on("error", finish)
})

// CVE-2026-24842 + CVE-2026-29786: absolute symlink linkpath with '..' is stripped
// (Depends on CVE-2026-24842 allowing '..' for symlinks)
tap.test("CVE-2026-24842: absolute symlink linkpath with '..' is stripped and allowed", function (t) {
  rimraf.sync(target)
  var tarBuf = buildTar([
    { path: "a/", type: "5", mode: 0755 },
    { path: "a/link", type: "2", linkpath: "/../a/target" }
  ])
  fs.writeFileSync(tarFile, tarBuf)

  var extractor = tar.Extract({ path: target })
    .on("end", function () {
      try {
        var linkTarget = fs.readlinkSync(path.resolve(target, "a/link"))
        t.equal(linkTarget.charAt(0) !== "/" || linkTarget === "../a/target", true,
          "absolute prefix stripped from symlink linkpath: got " + linkTarget)
      } catch (err) {
        t.fail("symlink should have been created: " + err.message)
      }
      t.end()
    })

  fs.createReadStream(tarFile).pipe(extractor)
})

// CVE-2026-24842 + CVE-2026-29786: Windows drive-relative symlink linkpath stripped
// (Depends on CVE-2026-24842 allowing '..' for symlinks)
tap.test("CVE-2026-24842: Windows drive-relative symlink linkpath has drive prefix stripped", function (t) {
  rimraf.sync(target)
  var tarBuf = buildTar([
    { path: "a/", type: "5", mode: 0755 },
    { path: "a/winrootdotslink", type: "2", linkpath: "c:..\\foo\\bar" }
  ])
  fs.writeFileSync(tarFile, tarBuf)

  var extractor = tar.Extract({ path: target })
    .on("end", function () {
      try {
        var linkTarget = fs.readlinkSync(path.resolve(target, "a/winrootdotslink"))
        t.equal(linkTarget.indexOf("c:"), -1,
          "drive prefix 'c:' stripped from symlink linkpath: got " + linkTarget)
      } catch (err) {
        t.fail("symlink should have been created with stripped linkpath: " + err.message)
      }
      t.end()
    })

  fs.createReadStream(tarFile).pipe(extractor)
})

// CVE-2026-31802: drive-prefix path cleaned via parts.join before resolve
tap.test("CVE-2026-31802: drive-prefix path cleaned via parts.join before resolve", function (t) {
  rimraf.sync(target)
  var tarBuf = buildTar([
    { path: "c:foo/inner.txt", type: "0", size: 0 }
  ])
  fs.writeFileSync(tarFile, tarBuf)

  var extractor = tar.Extract({ path: target })
    .on("end", function () {
      var expected = path.resolve(target, "foo/inner.txt")
      var exists = false
      try { fs.statSync(expected); exists = true } catch (e) {}
      t.equal(exists, true,
        "drive-prefix 'c:foo/inner.txt' should extract to target/foo/inner.txt after stripping")
      t.end()
    })

  fs.createReadStream(tarFile).pipe(extractor)
})

function runChainExploitTest(t, linkType, typeName) {
  rimraf.sync(target)
  mkdirp.sync(target)
  var exploitedName = "exploited-" + typeName + "-" + process.pid + ".txt"
  var exploitedFile = path.resolve(target, "..", exploitedName)
  fs.writeFileSync(exploitedFile, "original content")

  var tarBuf = buildTar([
    { path: "a/", type: "5", mode: 0755 },
    { path: "a/b/", type: "5", mode: 0755 },
    { path: "a/b/up", type: "2", linkpath: "../.." },
    { path: "a/b/escape", type: "2", linkpath: "up/.." },
    { path: "exploit", type: linkType, linkpath: "a/b/escape/" + exploitedName }
  ])
  fs.writeFileSync(tarFile, tarBuf)

  var done = false
  function finish() {
    if (done) return
    done = true
    try { fs.writeFileSync(path.resolve(target, "exploit"), "pwned") } catch (e) {}
    t.equal(fs.readFileSync(exploitedFile, 'utf8'), "original content",
      "external exploited-file must NOT be modified via " + typeName + " chain")
    try { fs.unlinkSync(exploitedFile) } catch (e) {}
    t.end()
  }

  var extractor = tar.Extract({ path: target })
    .on("end", finish)
    .on("error", finish)
  var rs = fs.createReadStream(tarFile)
  rs.on("error", finish)
  rs.pipe(extractor).on("error", finish)
}

tap.test("CVE-2026-26960: symlink chain exploit blocked (Link type)", function (t) {
  runChainExploitTest(t, "1", "Link")
})

tap.test("CVE-2026-26960: symlink chain exploit blocked (SymbolicLink type)", function (t) {
  runChainExploitTest(t, "2", "SymbolicLink")
})

tap.test("cleanup", function (t) {
  rimraf.sync(target)
  rimraf.sync(tarFile)
  t.pass("cleaned")
  t.end()
})
