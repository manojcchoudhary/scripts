# Bill Gates once said, "I choose a lazy person to do a hard job. Because a lazy person will find an easy way to do it."
# Add the below to your cli profile. In my case it's ~/.zshrc. Don't forget to source the file to reload.
# Usage : mvnver in your maven project

mvnver() {
  echo
  read "base?Enter base version (e.g. 0.1.0): "

  echo
  echo "Choose release type:"
  select type in SNAPSHOT alpha beta rc release; do
    [[ -n $type ]] && break
  done

  local version

  case $type in
    SNAPSHOT)
      version="${base}-SNAPSHOT"
      ;;
    alpha)
      version="${base}-alpha"
      ;;
    beta|rc)
      read "num?Enter $type number (e.g. 1): "
      version="${base}-${type}.${num}"
      ;;
    release)
      version="${base}"
      ;;
  esac

  echo
  echo "Setting version to: $version"
  mvn versions:set -DnewVersion="$version" -DgenerateBackupPoms=false
}
