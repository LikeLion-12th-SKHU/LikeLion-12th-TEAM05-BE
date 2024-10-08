package org.likelion.likelion_12th_team05.location.api.dto.response;

import lombok.Builder;
import org.likelion.likelion_12th_team05.location.domain.Location;

@Builder
public record LocationInfoResDto(
        Long locationId,
        Long curationId,
        String name,
        String description,
        String address,
        String locationImage,
        Double longitude,
        Double latitude
) {
    public static LocationInfoResDto from(Location location) {
        return LocationInfoResDto.builder()
                .locationId(location.getId())
                .curationId(location.getCuration().getId())
                .name(location.getName())
                .description(location.getDescription())
                .address(location.getAddress())
                .locationImage(location.getLocationImage())
                .longitude(location.getLongitude())
                .latitude(location.getLatitude())
                .build();
    }
}
