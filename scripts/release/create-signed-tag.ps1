param(
    [Parameter(Mandatory = $true)] [string] $Version,
    [string] $GpgKeyId
)

$ErrorActionPreference = "Stop"
if (git rev-parse -q --verify "refs/tags/$Version") {
    throw "tag already exists: $Version"
}

if ($GpgKeyId) {
    git tag -s $Version -u $GpgKeyId -m "HYDRA-MSG $Version"
} else {
    git tag -s $Version -m "HYDRA-MSG $Version"
}
git tag -v $Version
Write-Host "Signed Git tag created: $Version"
