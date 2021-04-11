#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (C) 2021 Olliver Schinagl <oliver@schinagl.nl>
# Copyright (C) 2021 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

set -eu

DEF_CLAMAV_DOCKER_IMAGE="clamav/clamav"
DEF_DOCKER_REGISTRY="registry.hub.docker.com"


usage()
{
	echo "Usage: ${0} [OPTIONS]"
	echo "Update docker images with latest clamav database."
	echo "    -h  Print this usage"
	echo "    -i  Image to use to use (default: '${DEF_CLAMAV_DOCKER_IMAGE}') [CLAMAV_DOCKER_IMAGE]"
	echo "    -p  Password for docker registry (file or string) [CLAMAV_DOCKER_PASSWD]"
	echo "    -r  Registry to use to push docker images to (default: '${DEF_DOCKER_REGISTRY}') [DOCKER_REGISTRY]"
	echo "    -t  Tag(s) to update (default: all tags)"
	echo "    -u  Username for docker registry [CLAMAV_DOCKER_USER]"
	echo
	echo "Options that can also be passed in environment variables listed between [BRACKETS]."
}

init()
{
	if [ -z "${clamav_docker_user:-}" ] ||
           [ -z "${clamav_docker_passwd:-}" ]; then
		echo "No username or password set, skipping login"
		return
	fi

	docker --version

	if [ -f "${clamav_docker_passwd}" ]; then
		_passwd="$(cat "${clamav_docker_passwd}")"
	fi
	echo "${_passwd:-${clamav_docker_passwd}}" | \
	docker login \
	             --password-stdin \
	             --username "${clamav_docker_user}" \
	             "${docker_registry}"
}

cleanup()
{
	if [ -z "${clamav_docker_user:-}" ]; then
		echo "No username set, skipping logout"
		return
	fi

	docker logout "${docker_registry:-}"
}

docker_tags_get()
{
	if [ -n "${clamav_docker_tags:-}" ]; then
		return
	fi

	_tags="$(wget -q -O - "https://${docker_registry}/v1/repositories/${clamav_docker_image}/tags" |
	         sed -e 's|[][]||g' -e 's|"||g' -e 's| ||g' | \
		 tr '}' '\n' | \
		 sed -n -e 's|.*name:\(.*\)$|\1|p')"

	for _tag in ${_tags}; do
		if [ "${_tag%%_base}" != "${_tag}" ]; then
			clamav_docker_tags="${_tag} ${clamav_docker_tags:-}"
		fi
	done
}

clamav_db_update()
{
	if [ -z "${clamav_docker_tags:-}" ]; then
		echo "No tags to update with, cannot continue."
		exit 1
	fi

	for _tag in ${clamav_docker_tags}; do
		{
			echo "FROM ${docker_registry}/${clamav_docker_image}:${_tag}"
			echo "RUN freshclam --foreground --stdout"
		} | docker image build --pull --rm --tag "${docker_registry}/${clamav_docker_image}:${_tag%%_base}" -
		docker image push "${docker_registry}/${clamav_docker_image}:${_tag%%_base}"
	done
}

main()
{
	_start_time="$(date "+%s")"

	while getopts ":hi:p:r:t:u:" _options; do
		case "${_options}" in
		h)
			usage
			exit 0
			;;
		i)
			clamav_docker_image="${OPTARG}"
			;;
		p)
			clamav_docker_passwd="${OPTARG}"
			;;
		r)
			docker_registry="${OPTARG}"
			;;
		t)
			clamav_docker_tag="${OPTARG}"
			;;
		u)
			clamav_docker_user="${OPTARG}"
			;;
		:)
			e_err "Option -${OPTARG} requires an argument."
			exit 1
			;;
		?)
			e_err "Invalid option: -${OPTARG}"
			exit 1
			;;
		esac
	done
	shift "$((OPTIND - 1))"

	clamav_docker_image="${clamav_docker_image:-${CLAMAV_DOCKER_IMAGE:-${DEF_CLAMAV_DOCKER_IMAGE}}}"
	clamav_docker_passwd="${clamav_docker_passwd:-${CLAMAV_DOCKER_PASSWD:-}}"
	clamav_docker_tag="${clamav_docker_tag:-}"
	clamav_docker_user="${clamav_docker_user:-${CLAMAV_DOCKER_USER:-}}"
	docker_registry="${docker_registry:-${DOCKER_REGISTRY:-${DEF_DOCKER_REGISTRY}}}"

	init

	docker_tags_get
	clamav_db_update

	echo "==============================================================================="
	echo "Build report for $(date -u)"
	echo
	echo "Updated database for image tags ..."
	echo "${clamav_docker_tags:-}"
	echo
	echo "... successfully in $(($(date "+%s") - _start_time)) seconds"
	echo "==============================================================================="

	cleanup
}

main "${@}"

exit 0
